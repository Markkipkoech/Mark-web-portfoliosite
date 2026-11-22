import hashlib
import json
import sys
import unittest
from dataclasses import replace
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "portfolio-data" / "scripts"))

from candidate_screening import (
    GitleaksAdapter,
    GitleaksPin,
    ProcessResult,
    ScreeningResult,
    ScreeningStatus,
    screen_candidate,
)
from candidate_identity import identify_candidate
from discover_candidates import (
    CandidateIssueCode,
    DiscoveryFailure,
    DiscoveryFailureCode,
    candidate_path_parts,
    discover_pinned_source,
    prepare_registered_source,
)
from trusted_source import (
    APIErrorCategory,
    BlobMetadata,
    CommitMetadata,
    GitHubAPIError,
    InstallationMetadata,
    InstallationRepositories,
    RepositoryMetadata,
    TreeEntry,
    TreeResponse,
)
from validate_portfolio_update import MAX_JSON_BYTES


REPOSITORY_ID = 123456789
APP_ID = 456
INSTALLATION_ID = 789
COMMIT_A = "a" * 40
COMMIT_B = "f" * 40
ROOT_TREE = "b" * 40
_USE_ACTUAL_SIZE = object()


def git_blob_sha(content):
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()


def candidate_bytes(update_id="milestone-one", title="Verified milestone"):
    value = {
        "schema_version": "1.0",
        "project_id": "companyhub",
        "update_id": update_id,
        "date": "2026-11-19",
        "category": "engineering",
        "title": title,
        "summary": "A factual engineering update.",
        "highlights": ["A verified implementation detail."],
        "technologies": ["Python"],
        "evidence": ["https://github.com/example/project"],
        "destination": "engineering",
    }
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class FakeDiscoveryClient:
    def __init__(self, files=(), truncated_paths=()):
        self.repository = RepositoryMetadata(
            REPOSITORY_ID, "Markkipkoech/CompanyHub", "main"
        )
        self.installation = InstallationMetadata(
            INSTALLATION_ID, APP_ID, (("contents", "read"),)
        )
        self.installation_repositories = InstallationRepositories(
            (REPOSITORY_ID,), True
        )
        self.repository_id = REPOSITORY_ID
        self.installation_id = INSTALLATION_ID
        self.contents_permission = "read"
        self.branch_head_sha = COMMIT_A
        self.commits = {
            COMMIT_A: CommitMetadata(COMMIT_A, ROOT_TREE),
            COMMIT_B: CommitMetadata(COMMIT_B, ROOT_TREE),
        }
        self.errors = {}
        self.calls = []
        self.branch_head_calls = 0
        self.commit_calls = []
        self.tree_calls = []
        self.blob_calls = []
        self.blobs = {}
        self.trees = {}
        self.truncated_paths = set(truncated_paths)
        self._install_files(files)

    def _raise_if_configured(self, endpoint):
        error = self.errors.get(endpoint)
        if error is not None:
            raise error

    def _install_files(self, files):
        root = {}
        for path, content, mode, object_type, declared_size in files:
            parts = path.split("/")
            current = root
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            if object_type == "tree":
                current[parts[-1]] = {}
                continue
            if object_type == "blob":
                sha = git_blob_sha(content)
                self.blobs[sha] = BlobMetadata(sha, len(content), content)
            else:
                sha = "9" * 40
            if object_type in {"tree", "commit"}:
                size = None
            else:
                size = len(content) if declared_size is _USE_ACTUAL_SIZE else declared_size
            current[parts[-1]] = (TreeEntry(parts[-1], mode, object_type, sha, size))

        next_tree_id = 100

        def build(node, prefix, tree_sha):
            nonlocal next_tree_id
            entries = []
            for name in sorted(node):
                child = node[name]
                if isinstance(child, dict):
                    child_sha = "{:040x}".format(next_tree_id)
                    next_tree_id += 1
                    entries.append(TreeEntry(name, "040000", "tree", child_sha))
                    build(child, "{}/{}".format(prefix, name) if prefix else name, child_sha)
                else:
                    entries.append(child)
            self.trees[tree_sha] = TreeResponse(
                tree_sha, tuple(entries), prefix in self.truncated_paths
            )

        build(root, "", ROOT_TREE)

    def get_repository_by_id(self, repository_id):
        self.calls.append(("repository", repository_id))
        self._raise_if_configured("repository")
        return self.repository

    def get_repository_installation(self, repository_id):
        self.calls.append(("repository_installation", repository_id))
        self._raise_if_configured("repository_installation")
        return self.installation

    def list_installation_repositories(self, installation_id):
        self.calls.append(("installation_repositories", installation_id))
        self._raise_if_configured("installation_repositories")
        return self.installation_repositories

    def create_repository_scoped_client(
        self, installation_id, repository_id, *, permissions
    ):
        self.calls.append(("scoped_client", installation_id, repository_id))
        self._raise_if_configured("scoped_client")
        return self

    def get_branch_head_sha(self, branch):
        self.calls.append(("branch_head", branch))
        self.branch_head_calls += 1
        self._raise_if_configured("branch_head")
        return self.branch_head_sha

    def get_commit(self, commit_sha):
        self.calls.append(("commit", commit_sha))
        self.commit_calls.append(commit_sha)
        self._raise_if_configured("commit")
        return self.commits[commit_sha]

    def get_tree(self, tree_sha, *, recursive):
        self.calls.append(("tree", tree_sha))
        self.tree_calls.append(tree_sha)
        self._raise_if_configured("tree")
        return self.trees[tree_sha]

    def get_blob(self, blob_sha):
        self.calls.append(("blob", blob_sha))
        self.blob_calls.append(blob_sha)
        self._raise_if_configured("blob")
        return self.blobs[blob_sha]


class FakeGitleaksRunner:
    def __init__(self, *, finding_marker=None, error_marker=None):
        self.finding_marker = finding_marker
        self.error_marker = error_marker
        self.calls = []

    def run(
        self, argv, *, stdin, timeout_seconds, max_output_bytes,
        expected_binary_sha256, expected_configuration_sha256,
        expected_ignore_sha256, expected_executable,
        expected_configuration_path, expected_ignore_path,
    ):
        self.calls.append((argv, stdin))
        if len(argv) == 2 and argv[1] == "version":
            return ProcessResult(0, b"8.25.0")
        if self.error_marker and self.error_marker in stdin:
            return ProcessResult(2, b"[]")
        if self.finding_marker and self.finding_marker in stdin:
            report = [{"RuleID": "synthetic_secret", "StartLine": 1}]
            return ProcessResult(1, json.dumps(report).encode("utf-8"))
        return ProcessResult(0, b"[]")


class CandidateDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(
            (REPOSITORY_ROOT / "portfolio-data/schemas/portfolio-update.schema.json")
            .read_text(encoding="utf-8")
        )

    def setUp(self):
        self.registry = {
            "schema_version": "1.0",
            "projects": {
                "companyhub": {
                    "repository": "Markkipkoech/CompanyHub",
                    "repository_id": REPOSITORY_ID,
                    "display_name": "CompanyHub",
                    "enabled": True,
                    "destinations": ["projects", "engineering"],
                }
            },
        }

    def _file(
        self,
        update_id,
        sequence,
        raw=None,
        mode="100644",
        object_type="blob",
        declared_size=_USE_ACTUAL_SIZE,
    ):
        path = ".portfolio/updates/{}/candidate-{}.json".format(update_id, sequence)
        content = candidate_bytes(update_id, "Version {}".format(sequence)) if raw is None else raw
        return (path, content, mode, object_type, declared_size)

    def _prepare(self, client):
        return prepare_registered_source(
            "companyhub", self.registry, client, expected_app_id=APP_ID
        )

    def _screening_adapter(self, runner=None):
        binary = b"test-only-gitleaks-binary"
        configuration = b""
        ignore = b""
        pin = GitleaksPin(
            executable="test-gitleaks",
            version="8.25.0",
            binary_sha256=hashlib.sha256(binary).hexdigest(),
            configuration_path="test-gitleaks.toml",
            configuration_sha256=hashlib.sha256(configuration).hexdigest(),
            ignore_path="test-gitleaks-ignore",
            ignore_sha256=hashlib.sha256(ignore).hexdigest(),
        )
        return GitleaksAdapter(
            pin,
            runner or FakeGitleaksRunner(),
            binary_reader=lambda _path: binary,
            configuration_reader=lambda _path: configuration,
            ignore_reader=lambda _path: ignore,
            timeout_seconds=3,
            max_output_bytes=8192,
        )

    def _discover(self, client, pin, screening_adapter=None):
        with patch("discover_candidates.validate_candidate_data", return_value=[]):
            return discover_pinned_source(
                pin,
                "companyhub",
                self.registry,
                self.schema,
                screening_adapter=screening_adapter or self._screening_adapter(),
            )

    def test_screening_adapter_is_mandatory_and_configuration_failure_is_sanitized(self):
        client = FakeDiscoveryClient([self._file("adapter-required", "001")])
        pin = self._prepare(client)
        with self.assertRaises(DiscoveryFailure) as raised:
            discover_pinned_source(pin, "companyhub", self.registry, self.schema)
        self.assertEqual(
            raised.exception.code,
            DiscoveryFailureCode.SCREENING_CONFIGURATION_FAILURE,
        )
        self.assertNotIn("test-gitleaks", str(raised.exception))

    def test_clean_candidate_carries_its_screening_result(self):
        client = FakeDiscoveryClient([self._file("clean-candidate", "001")])
        batch = self._discover(client, self._prepare(client))
        self.assertEqual(len(batch.candidates), 1)
        self.assertIs(
            batch.candidates[0].screening_result.status, ScreeningStatus.CLEAN
        )
        self.assertTrue(batch.screening_complete)
        self.assertEqual(batch.screening_findings, ())
        self.assertEqual(batch.screening_errors, ())

    def test_privacy_finding_excludes_candidate_but_preserves_revision_lineage(self):
        first_raw = candidate_bytes("privacy-history", "Contact private@example.com")
        second_raw = candidate_bytes("privacy-history", "A later safe milestone")
        client = FakeDiscoveryClient([
            self._file("privacy-history", "001", raw=first_raw),
            self._file("privacy-history", "002", raw=second_raw),
        ])
        batch = self._discover(client, self._prepare(client))
        self.assertEqual([item.sequence for item in batch.candidates], [2])
        self.assertEqual(len(batch.screening_findings), 1)
        finding = batch.screening_findings[0]
        self.assertEqual(finding.sequence, 1)
        self.assertIs(finding.screening_result.status, ScreeningStatus.FINDING)
        self.assertEqual(
            batch.candidates[0].previous_submission_id,
            identify_candidate(first_raw).submission_id,
        )
        self.assertEqual(batch.candidates[0].revision_kind, "canonical_revision")
        self.assertTrue(batch.screening_complete)
        self.assertNotIn("private@example.com", repr(batch.screening_findings))

    def test_gitleaks_finding_is_separate_from_candidate_issues(self):
        raw = candidate_bytes("secret-history", "Contains synthetic_secret_marker")
        client = FakeDiscoveryClient([
            self._file("secret-history", "001", raw=raw)
        ])
        adapter = self._screening_adapter(
            FakeGitleaksRunner(finding_marker=b"synthetic_secret_marker")
        )
        batch = self._discover(client, self._prepare(client), adapter)
        self.assertEqual(batch.candidates, ())
        self.assertEqual(batch.issues, ())
        self.assertEqual(len(batch.screening_findings), 1)
        result = batch.screening_findings[0].screening_result
        self.assertIs(result.status, ScreeningStatus.FINDING)
        self.assertTrue(result.gitleaks_identity)
        self.assertEqual(len(result.findings), 1)

    def test_scanner_error_keeps_clean_candidates_and_retry_rescans_same_pin(self):
        failed_raw = candidate_bytes("retry-history", "scanner_error_marker")
        clean_raw = candidate_bytes("retry-history", "A clean later revision")
        client = FakeDiscoveryClient([
            self._file("retry-history", "001", raw=failed_raw),
            self._file("retry-history", "002", raw=clean_raw),
        ])
        pin = self._prepare(client)
        failing_adapter = self._screening_adapter(
            FakeGitleaksRunner(error_marker=b"scanner_error_marker")
        )
        first_batch = self._discover(client, pin, failing_adapter)
        self.assertEqual([item.sequence for item in first_batch.candidates], [2])
        self.assertEqual(len(first_batch.screening_errors), 1)
        self.assertIs(
            first_batch.screening_errors[0].screening_result.status,
            ScreeningStatus.SCANNER_ERROR,
        )
        self.assertFalse(first_batch.screening_complete)
        self.assertEqual(
            first_batch.candidates[0].previous_submission_id,
            identify_candidate(failed_raw).submission_id,
        )
        self.assertNotIn("scanner_error_marker", repr(first_batch.screening_errors))

        retry_runner = FakeGitleaksRunner()
        retry_batch = self._discover(
            client, pin, self._screening_adapter(retry_runner)
        )
        self.assertEqual(retry_batch.source_commit_sha, first_batch.source_commit_sha)
        self.assertEqual([item.sequence for item in retry_batch.candidates], [1, 2])
        self.assertTrue(retry_batch.screening_complete)
        self.assertEqual(retry_batch.screening_errors, ())
        self.assertEqual(
            sum(
                1 for argv, _stdin in retry_runner.calls
                if len(argv) == 2 and argv[1] == "version"
            ),
            2,
        )

    def test_invalid_or_wrong_candidate_screening_response_fails_closed(self):
        raw = candidate_bytes("invalid-screening-response", "Verified milestone")
        adapter = self._screening_adapter()
        valid_response = screen_candidate(raw, adapter)
        wrong_digest = replace(
            valid_response,
            raw_candidate_sha256="0" * 64,
        )

        for response in (wrong_digest, object()):
            with self.subTest(response_type=type(response).__name__):
                client = FakeDiscoveryClient([
                    self._file("invalid-screening-response", "001", raw=raw)
                ])
                pin = self._prepare(client)

                with patch(
                    "discover_candidates.screen_candidate",
                    return_value=response,
                ):
                    batch = self._discover(client, pin, adapter)

                self.assertEqual(batch.candidates, ())
                self.assertEqual(len(batch.screening_errors), 1)
                result = batch.screening_errors[0].screening_result
                self.assertIs(result.status, ScreeningStatus.SCANNER_ERROR)
                self.assertEqual(result.error_code, "screening_response_invalid")
                self.assertFalse(batch.screening_complete)

    def test_exact_path_acceptance_boundaries_and_adversarial_rejection(self):
        accepted = {
            ".portfolio/updates/a/candidate-001.json": ("a", 1),
            ".portfolio/updates/z9-feature/candidate-999.json": ("z9-feature", 999),
        }
        for path, expected in accepted.items():
            with self.subTest(path=path):
                self.assertEqual(candidate_path_parts(path), expected)
        rejected = (
            ".portfolio/updates/a/candidate-000.json",
            ".portfolio/updates/a/candidate-01.json",
            ".portfolio/updates/a/candidate-1000.json",
            ".portfolio/updates/A/candidate-001.json",
            ".portfolio/updates/a/candidate-001.JSON",
            ".portfolio//updates/a/candidate-001.json",
            ".portfolio/updates/a/nested/candidate-001.json",
            ".portfolio/updates/../a/candidate-001.json",
            r".portfolio\updates\a\candidate-001.json",
            ".portfolio/updates/é/candidate-001.json",
        )
        for path in rejected:
            with self.subTest(path=path):
                self.assertIsNone(candidate_path_parts(path))

    def test_sequence_gaps_and_deterministic_update_sequence_order(self):
        files = [
            self._file("beta", "003"),
            self._file("alpha", "009"),
            self._file("alpha", "001"),
        ]
        client = FakeDiscoveryClient(files)
        batch = self._discover(client, self._prepare(client))
        self.assertEqual(
            [(item.update_id, item.sequence) for item in batch.candidates],
            [("alpha", 1), ("alpha", 9), ("beta", 3)],
        )

    def test_nested_candidate_path_is_not_selected(self):
        nested = self._file("milestone-one", "001")
        nested = (nested[0].replace("candidate-001", "nested/candidate-001"),) + nested[1:]
        client = FakeDiscoveryClient([nested])
        batch = self._discover(client, self._prepare(client))
        self.assertEqual(batch.candidates, ())
        self.assertEqual(client.blob_calls, [])

    def test_regular_blob_is_accepted_and_non_regular_types_are_excluded(self):
        files = [
            self._file("regular", "001"),
            self._file("symlink", "001", mode="120000"),
            self._file("submodule", "001", mode="160000", object_type="commit"),
            self._file("unsupported", "001", mode="040000", object_type="tree"),
        ]
        client = FakeDiscoveryClient(files)
        batch = self._discover(client, self._prepare(client))
        self.assertEqual([item.update_id for item in batch.candidates], ["regular"])
        self.assertEqual(
            [issue.code for issue in batch.issues],
            [CandidateIssueCode.UNSUPPORTED_FILE_TYPE] * 3,
        )

    def test_unsupported_git_blob_mode_fails_closed(self):
        client = FakeDiscoveryClient(
            [self._file("unsupported-mode", "001", mode="100600")]
        )
        with self.assertRaises(DiscoveryFailure) as raised:
            self._discover(client, self._prepare(client))
        self.assertEqual(
            raised.exception.code, DiscoveryFailureCode.SOURCE_CONTRACT_FAILURE
        )
        self.assertEqual(client.blob_calls, [])

    def test_declared_candidate_size_is_checked_before_blob_read(self):
        item = self._file("too-large", "001", declared_size=MAX_JSON_BYTES + 1)
        client = FakeDiscoveryClient([item])
        batch = self._discover(client, self._prepare(client))
        self.assertEqual(batch.candidates, ())
        self.assertEqual(client.blob_calls, [])
        self.assertEqual(batch.issues[0].code, CandidateIssueCode.CANDIDATE_TOO_LARGE)

    def test_missing_declared_candidate_size_fails_closed(self):
        item = self._file("unknown-size", "001", declared_size=None)
        client = FakeDiscoveryClient([item])
        batch = self._discover(client, self._prepare(client))
        self.assertEqual(batch.candidates, ())
        self.assertEqual(client.blob_calls, [])
        self.assertEqual(batch.issues[0].code, CandidateIssueCode.DECLARED_SIZE_MISSING)

    def test_actual_candidate_size_is_checked_after_verified_blob_read(self):
        client = FakeDiscoveryClient([self._file("actual-large", "001")])
        pin = self._prepare(client)
        with patch("discover_candidates.validate_candidate_data", return_value=[]), patch(
            "discover_candidates._read_candidate_blob",
            return_value=b"x" * (MAX_JSON_BYTES + 1),
        ):
            batch = self._discover(client, pin)
        self.assertEqual(batch.candidates, ())
        self.assertEqual(batch.issues[0].code, CandidateIssueCode.CANDIDATE_TOO_LARGE)

    def test_malformed_json_and_schema_semantic_failures_are_candidate_issues(self):
        malformed = self._file("bad-json", "001", raw=b'{"secret":"private"')
        invalid = json.loads(candidate_bytes("bad-schema"))
        invalid["unexpected"] = "private-value"
        invalid["destination"] = "learning-journal"
        bad_schema = self._file(
            "bad-schema", "001", raw=json.dumps(invalid).encode("utf-8")
        )
        client = FakeDiscoveryClient([malformed, bad_schema])
        pin = self._prepare(client)
        with patch(
            "discover_candidates.validate_candidate_data",
            side_effect=lambda candidate, schema, registry: (
                ["validation failed"] if "unexpected" in candidate else []
            ),
        ):
            batch = discover_pinned_source(
                pin,
                "companyhub",
                self.registry,
                self.schema,
                screening_adapter=self._screening_adapter(),
            )
        self.assertEqual(batch.candidates, ())
        self.assertEqual(
            {issue.code for issue in batch.issues},
            {
                CandidateIssueCode.INVALID_JSON_OR_IDENTITY,
                CandidateIssueCode.VALIDATION_FAILED,
            },
        )
        self.assertNotIn("private", str(batch.issues))

    def test_update_id_path_and_trusted_project_mismatches_are_excluded(self):
        wrong_update = self._file(
            "path-update", "001", raw=candidate_bytes("different-update")
        )
        wrong_project_value = json.loads(candidate_bytes("wrong-project"))
        wrong_project_value["project_id"] = "backend-engineering-learning-journey"
        wrong_project = self._file(
            "wrong-project", "001", raw=json.dumps(wrong_project_value).encode()
        )
        client = FakeDiscoveryClient([wrong_update, wrong_project])
        batch = self._discover(client, self._prepare(client))
        self.assertEqual(batch.candidates, ())
        self.assertEqual(
            {issue.code for issue in batch.issues},
            {CandidateIssueCode.PATH_UPDATE_ID_MISMATCH, CandidateIssueCode.PROJECT_ID_MISMATCH},
        )

    def test_missing_repository_id_fails_before_source_api_calls(self):
        del self.registry["projects"]["companyhub"]["repository_id"]
        client = FakeDiscoveryClient()
        with self.assertRaises(DiscoveryFailure) as raised:
            self._prepare(client)
        self.assertEqual(raised.exception.code, DiscoveryFailureCode.REPOSITORY_ID_REQUIRED)
        self.assertEqual(client.branch_head_calls, 0)

    def test_disabled_project_fails_before_any_source_api_calls(self):
        self.registry["projects"]["companyhub"]["enabled"] = False
        client = FakeDiscoveryClient([self._file("milestone-one", "001")])

        with self.assertRaises(DiscoveryFailure) as raised:
            self._prepare(client)

        self.assertEqual(raised.exception.code, DiscoveryFailureCode.PROJECT_DISABLED)
        self.assertEqual(client.calls, [])
        self.assertEqual(client.branch_head_calls, 0)
        self.assertEqual(client.commit_calls, [])
        self.assertEqual(client.tree_calls, [])
        self.assertEqual(client.blob_calls, [])

    def test_discovery_rechecks_disabled_project_before_pinned_source_access(self):
        client = FakeDiscoveryClient([self._file("milestone-one", "001")])
        pin = self._prepare(client)
        calls_before_discovery = len(client.calls)
        self.registry["projects"]["companyhub"]["enabled"] = False

        with self.assertRaises(DiscoveryFailure) as raised:
            self._discover(client, pin)

        self.assertEqual(raised.exception.code, DiscoveryFailureCode.PROJECT_DISABLED)
        self.assertEqual(client.calls[calls_before_discovery:], [])
        self.assertEqual(client.commit_calls, [])
        self.assertEqual(client.tree_calls, [])
        self.assertEqual(client.blob_calls, [])

    def test_discovery_rejects_changed_registry_repository_before_pinned_source_access(self):
        for field, changed_value in (
            ("repository_id", REPOSITORY_ID + 1),
            ("repository", "Markkipkoech/RenamedCompanyHub"),
        ):
            with self.subTest(field=field):
                self.registry["projects"]["companyhub"] = {
                    "repository": "Markkipkoech/CompanyHub",
                    "repository_id": REPOSITORY_ID,
                    "display_name": "CompanyHub",
                    "enabled": True,
                    "destinations": ["projects", "engineering"],
                }
                client = FakeDiscoveryClient([self._file("milestone-one", "001")])
                pin = self._prepare(client)
                calls_before_discovery = len(client.calls)
                self.registry["projects"]["companyhub"][field] = changed_value

                with self.assertRaises(DiscoveryFailure) as raised:
                    self._discover(client, pin)

                self.assertEqual(
                    raised.exception.code,
                    DiscoveryFailureCode.SOURCE_IDENTITY_OR_AUTHORIZATION,
                )
                self.assertEqual(client.calls[calls_before_discovery:], [])
                self.assertEqual(client.commit_calls, [])
                self.assertEqual(client.tree_calls, [])
                self.assertEqual(client.blob_calls, [])

    def test_repeated_discovery_has_same_observation_and_submission_identity(self):
        client = FakeDiscoveryClient([self._file("milestone-one", "001")])
        pin = self._prepare(client)
        first = self._discover(client, pin).candidates[0]
        second = self._discover(client, pin).candidates[0]
        self.assertEqual(first.observation_id, second.observation_id)
        self.assertEqual(first.identity.submission_id, second.identity.submission_id)
        self.assertEqual(client.branch_head_calls, 1)

    def test_same_bytes_at_a_different_commit_have_distinct_observations(self):
        client = FakeDiscoveryClient([self._file("milestone-one", "001")])
        first_pin = self._prepare(client)
        first = self._discover(client, first_pin).candidates[0]
        client.branch_head_sha = COMMIT_B
        second_pin = self._prepare(client)
        second = self._discover(client, second_pin).candidates[0]
        self.assertEqual(first.identity.raw_sha256, second.identity.raw_sha256)
        self.assertEqual(first.identity.submission_id, second.identity.submission_id)
        self.assertNotEqual(first.observation_id, second.observation_id)

    def test_formatting_only_versions_share_submission_and_link_as_formatting(self):
        compact = candidate_bytes("milestone-one")
        spaced = json.dumps(json.loads(compact), indent=2).encode("utf-8")
        client = FakeDiscoveryClient(
            [
                self._file("milestone-one", "001", raw=compact),
                self._file("milestone-one", "004", raw=spaced),
            ]
        )
        batch = self._discover(client, self._prepare(client))
        first, second = batch.candidates
        self.assertNotEqual(first.identity.raw_sha256, second.identity.raw_sha256)
        self.assertEqual(first.identity.canonical_sha256, second.identity.canonical_sha256)
        self.assertEqual(first.identity.submission_id, second.identity.submission_id)
        self.assertEqual(second.revision_kind, "formatting_only")
        self.assertEqual(second.previous_submission_id, first.identity.submission_id)

    def test_canonical_changes_under_same_pair_are_linked_revisions(self):
        client = FakeDiscoveryClient(
            [
                self._file("milestone-one", "001", raw=candidate_bytes(title="First")),
                self._file("milestone-one", "007", raw=candidate_bytes(title="Corrected")),
            ]
        )
        first, second = self._discover(client, self._prepare(client)).candidates
        self.assertNotEqual(first.identity.submission_id, second.identity.submission_id)
        self.assertEqual(second.revision_kind, "canonical_revision")
        self.assertEqual(second.previous_submission_id, first.identity.submission_id)

    def test_duplicate_raw_bytes_at_separate_sequences_are_integrity_conflict(self):
        raw = candidate_bytes("milestone-one")
        client = FakeDiscoveryClient(
            [
                self._file("milestone-one", "001", raw=raw),
                self._file("milestone-one", "002", raw=raw),
            ]
        )
        with self.assertRaises(DiscoveryFailure) as raised:
            self._discover(client, self._prepare(client))
        self.assertEqual(raised.exception.code, DiscoveryFailureCode.INTEGRITY_CONFLICT)

    def test_incomplete_root_and_nested_trees_return_no_partial_batch(self):
        for truncated in ("", ".portfolio/updates"):
            with self.subTest(truncated=truncated):
                client = FakeDiscoveryClient(
                    [self._file("milestone-one", "001")],
                    truncated_paths=(truncated,),
                )
                pin = self._prepare(client)
                with self.assertRaises(DiscoveryFailure) as raised:
                    self._discover(client, pin)
                self.assertEqual(raised.exception.code, DiscoveryFailureCode.INCOMPLETE_TREE)
                self.assertEqual(client.blob_calls, [])

    def test_transient_tree_and_blob_retries_reuse_the_pinned_source(self):
        for endpoint in ("tree", "blob"):
            with self.subTest(endpoint=endpoint):
                client = FakeDiscoveryClient([self._file("milestone-one", "001")])
                pin = self._prepare(client)
                client.errors[endpoint] = GitHubAPIError(
                    endpoint, APIErrorCategory.TRANSIENT
                )
                with self.assertRaises(DiscoveryFailure) as raised:
                    self._discover(client, pin)
                self.assertEqual(
                    raised.exception.code,
                    DiscoveryFailureCode.TRANSIENT_SOURCE_FAILURE,
                )
                client.branch_head_sha = COMMIT_B
                client.commits[COMMIT_B] = CommitMetadata(COMMIT_B, "c" * 40)
                del client.errors[endpoint]
                batch = self._discover(client, pin)
                self.assertEqual(len(batch.candidates), 1)
                self.assertEqual(client.branch_head_calls, 1)
                self.assertEqual(client.commit_calls, [COMMIT_A, COMMIT_A])
                self.assertNotIn("c" * 40, client.tree_calls)

    def test_rate_limit_is_retryable_and_malformed_blob_fails_closed(self):
        client = FakeDiscoveryClient([self._file("milestone-one", "001")])
        pin = self._prepare(client)
        client.errors["blob"] = GitHubAPIError(
            "blob", APIErrorCategory.RATE_LIMITED, retry_after_seconds=10
        )
        with self.assertRaises(DiscoveryFailure) as raised:
            self._discover(client, pin)
        self.assertEqual(
            raised.exception.code, DiscoveryFailureCode.TRANSIENT_SOURCE_FAILURE
        )

        del client.errors["blob"]
        client.get_blob = lambda blob_sha: {"unexpected": "response"}
        with self.assertRaises(DiscoveryFailure) as raised:
            self._discover(client, pin)
        self.assertEqual(
            raised.exception.code, DiscoveryFailureCode.SOURCE_CONTRACT_FAILURE
        )

    def test_authorization_and_source_identity_failures_are_distinct(self):
        client = FakeDiscoveryClient()
        client.errors["repository_installation"] = GitHubAPIError(
            "repository_installation", APIErrorCategory.AUTHORIZATION
        )
        with self.assertRaises(DiscoveryFailure) as raised:
            self._prepare(client)
        self.assertEqual(
            raised.exception.code,
            DiscoveryFailureCode.SOURCE_IDENTITY_OR_AUTHORIZATION,
        )

        client = FakeDiscoveryClient()
        client.repository = RepositoryMetadata(
            REPOSITORY_ID + 1, "Markkipkoech/CompanyHub", "main"
        )
        with self.assertRaises(DiscoveryFailure) as raised:
            self._prepare(client)
        self.assertEqual(
            raised.exception.code,
            DiscoveryFailureCode.SOURCE_IDENTITY_OR_AUTHORIZATION,
        )

    def test_malformed_tree_response_fails_closed(self):
        client = FakeDiscoveryClient([self._file("milestone-one", "001")])
        pin = self._prepare(client)
        client.get_tree = lambda tree_sha, recursive=False: {"not": "a tree"}
        with self.assertRaises(DiscoveryFailure) as raised:
            self._discover(client, pin)
        self.assertEqual(raised.exception.code, DiscoveryFailureCode.SOURCE_CONTRACT_FAILURE)

    def test_no_durable_writes_or_payload_bearing_diagnostics(self):
        client = FakeDiscoveryClient(
            [self._file("bad-json", "001", raw=b'{"private":"do-not-print"')]
        )
        pin = self._prepare(client)
        stdout, stderr = StringIO(), StringIO()
        with patch.object(Path, "write_bytes", side_effect=AssertionError), patch.object(
            Path, "write_text", side_effect=AssertionError
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            batch = self._discover(client, pin)
        self.assertEqual(len(batch.issues), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("do-not-print", str(batch.issues))


if __name__ == "__main__":
    unittest.main()
