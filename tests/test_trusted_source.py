import hashlib
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "portfolio-data" / "scripts"))

from trusted_source import (
    APIErrorCategory,
    BlobMetadata,
    CommitMetadata,
    GitHubAPIError,
    InstallationMetadata,
    InstallationRepositories,
    RepositoryMetadata,
    SourceAuthorizationFailure,
    SourceContractFailure,
    SourceIncompleteTree,
    SourceIdentityMismatch,
    SourceRateLimited,
    SourceResourceNotFound,
    SourceTransientFailure,
    TreeEntry,
    TreeResponse,
    enumerate_tree,
    read_pinned_blob,
    registered_repository_from_entry,
    resolve_registered_source,
    verify_pinned_commit,
)


REPOSITORY_ID = 123456789
APP_ID = 456
INSTALLATION_ID = 789
COMMIT_SHA = "a" * 40
ADVANCED_COMMIT_SHA = "f" * 40
ROOT_TREE_SHA = "b" * 40
ADVANCED_TREE_SHA = "9" * 40
PORTFOLIO_TREE_SHA = "c" * 40
UPDATES_TREE_SHA = "d" * 40
UPDATE_TREE_SHA = "e" * 40


def git_blob_sha(content):
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


class FakeGitHubClient:
    """In-memory fake for both App metadata and repository-scoped reads."""

    def __init__(self):
        self.repository = RepositoryMetadata(
            REPOSITORY_ID, "Markkipkoech/CompanyHub", "main"
        )
        self.installation = InstallationMetadata(
            INSTALLATION_ID, APP_ID, (("contents", "read"),)
        )
        self.installation_repositories = InstallationRepositories(
            (REPOSITORY_ID,), True
        )
        self.scoped_repository_id = REPOSITORY_ID
        self.scoped_installation_id = INSTALLATION_ID
        self.scoped_contents_permission = "read"
        self.branch_head_sha = COMMIT_SHA
        self.commits = {COMMIT_SHA: CommitMetadata(COMMIT_SHA, ROOT_TREE_SHA)}
        self.content = b'{"project_id":"companyhub","update_id":"example-update"}'
        blob_sha = git_blob_sha(self.content)
        self.blob = BlobMetadata(blob_sha, len(self.content), self.content)
        self.trees = {
            ROOT_TREE_SHA: TreeResponse(
                ROOT_TREE_SHA,
                (TreeEntry(".portfolio", "040000", "tree", PORTFOLIO_TREE_SHA),),
                False,
            ),
            PORTFOLIO_TREE_SHA: TreeResponse(
                PORTFOLIO_TREE_SHA,
                (TreeEntry("updates", "040000", "tree", UPDATES_TREE_SHA),),
                False,
            ),
            UPDATES_TREE_SHA: TreeResponse(
                UPDATES_TREE_SHA,
                (TreeEntry("example-update", "040000", "tree", UPDATE_TREE_SHA),),
                False,
            ),
            UPDATE_TREE_SHA: TreeResponse(
                UPDATE_TREE_SHA,
                (
                    TreeEntry(
                        "candidate-001.json",
                        "100644",
                        "blob",
                        blob_sha,
                        len(self.content),
                    ),
                ),
                False,
            ),
        }
        self.errors = {}
        self.calls = []
        self.branch_head_calls = 0
        self.commit_calls = []
        self.tree_calls = []
        self.blob_calls = []

    def _raise_if_configured(self, endpoint):
        error = self.errors.get(endpoint)
        if error is not None:
            raise error

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
        self.calls.append(
            ("scoped_client", installation_id, repository_id, dict(permissions))
        )
        self._raise_if_configured("scoped_client")
        self.repository_id = self.scoped_repository_id
        self.installation_id = self.scoped_installation_id
        self.contents_permission = self.scoped_contents_permission
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
        self.tree_calls.append((tree_sha, recursive))
        self._raise_if_configured("tree")
        return self.trees[tree_sha]

    def get_blob(self, blob_sha):
        self.blob_calls.append(blob_sha)
        self._raise_if_configured("blob")
        return self.blob

    def get_file_by_branch(self, branch, path):
        self.calls.append(("branch_file", branch, path))
        raise AssertionError("branch-based file reads are forbidden")


class TrustedSourceTests(unittest.TestCase):
    def setUp(self):
        self.registry_entry = {
            "repository_id": REPOSITORY_ID,
            "repository": "Markkipkoech/CompanyHub",
        }
        self.registered = registered_repository_from_entry(
            "companyhub", self.registry_entry
        )
        self.client = FakeGitHubClient()

    def _pin(self):
        return resolve_registered_source(
            self.registered, self.client, expected_app_id=APP_ID
        )

    def _resolve(self):
        return verify_pinned_commit(self._pin())

    def _api_error(self, endpoint, category, **kwargs):
        return GitHubAPIError(endpoint, category, **kwargs)

    def test_resolves_registered_repository_and_pins_default_branch_once(self):
        pin = self._pin()

        self.assertEqual(pin.repository.repository_id, REPOSITORY_ID)
        self.assertEqual(pin.repository.full_name, "Markkipkoech/CompanyHub")
        self.assertEqual(pin.repository.default_branch, "main")
        self.assertEqual(pin.repository.commit_sha, COMMIT_SHA)
        self.assertFalse(hasattr(pin.repository, "tree_sha"))
        self.assertEqual(pin.repository.installation_id, INSTALLATION_ID)
        self.assertEqual(self.client.branch_head_calls, 1)
        self.assertEqual(self.client.commit_calls, [])
        self.assertIn(("branch_head", "main"), self.client.calls)

        resolved = verify_pinned_commit(pin)
        self.assertEqual(resolved.tree_sha, ROOT_TREE_SHA)
        self.assertEqual(self.client.branch_head_calls, 1)

    def test_registered_repository_requires_positive_integer_id(self):
        for repository_id in (None, 0, -1, True, "123456789", 1.5):
            with self.subTest(repository_id=repository_id):
                entry = dict(self.registry_entry, repository_id=repository_id)
                with self.assertRaises(SourceContractFailure):
                    registered_repository_from_entry("companyhub", entry)

    def test_registered_repository_name_must_be_well_formed(self):
        for name in ("CompanyHub", "/repo", "owner/", " owner/repo", "owner/repo "):
            with self.subTest(name=name):
                entry = dict(self.registry_entry, repository=name)
                with self.assertRaises(SourceContractFailure):
                    registered_repository_from_entry("companyhub", entry)

    def test_invalid_expected_app_id_fails_before_api_calls(self):
        for app_id in (0, -1, True, "456"):
            with self.subTest(app_id=app_id):
                with self.assertRaises(SourceContractFailure):
                    resolve_registered_source(
                        self.registered, self.client, expected_app_id=app_id
                    )
        self.assertEqual(self.client.calls, [])

    def test_repository_id_mismatch_fails_closed(self):
        self.client.repository = RepositoryMetadata(
            REPOSITORY_ID + 1, "Markkipkoech/CompanyHub", "main"
        )
        with self.assertRaises(SourceIdentityMismatch):
            self._resolve()

    def test_exact_registered_repository_name_is_required(self):
        self.client.repository = RepositoryMetadata(
            REPOSITORY_ID, "Markkipkoech/companyhub", "main"
        )
        with self.assertRaises(SourceIdentityMismatch):
            self._resolve()

    def test_rename_is_rejected_even_when_numeric_id_matches(self):
        self.client.repository = RepositoryMetadata(
            REPOSITORY_ID, "Markkipkoech/CompanyHub-Renamed", "main"
        )
        with self.assertRaises(SourceIdentityMismatch):
            self._resolve()

    def test_wrong_app_installation_fails_authorization(self):
        self.client.installation = InstallationMetadata(
            INSTALLATION_ID, APP_ID + 1, (("contents", "read"),)
        )
        with self.assertRaises(SourceAuthorizationFailure):
            self._resolve()

    def test_missing_installation_is_not_found_but_classified_as_authorization(self):
        self.client.errors["repository_installation"] = self._api_error(
            "repository_installation", APIErrorCategory.NOT_FOUND, status_code=404
        )
        with self.assertRaises(SourceAuthorizationFailure):
            self._resolve()

    def test_repository_not_in_installation_fails_authorization(self):
        self.client.installation_repositories = InstallationRepositories((42,), True)
        with self.assertRaises(SourceAuthorizationFailure):
            self._resolve()

    def test_incomplete_installation_listing_fails_closed(self):
        self.client.installation_repositories = InstallationRepositories(
            (REPOSITORY_ID,), False
        )
        with self.assertRaises(SourceContractFailure):
            self._resolve()

    def test_contents_permission_must_be_read_only(self):
        for permission in (None, "write", "admin"):
            with self.subTest(permission=permission):
                self.client.installation = InstallationMetadata(
                    INSTALLATION_ID,
                    APP_ID,
                    () if permission is None else (("contents", permission),),
                )
                with self.assertRaises(SourceAuthorizationFailure):
                    self._resolve()

    def test_repository_scoped_client_must_match_and_be_read_only(self):
        self.client.scoped_repository_id = REPOSITORY_ID + 1
        with self.assertRaises(SourceIdentityMismatch):
            self._resolve()

        self.client = FakeGitHubClient()
        self.client.scoped_installation_id = INSTALLATION_ID + 1
        with self.assertRaises(SourceIdentityMismatch):
            self._resolve()

        self.client = FakeGitHubClient()
        self.client.scoped_contents_permission = "write"
        with self.assertRaises(SourceAuthorizationFailure):
            self._resolve()

    def test_missing_default_branch_ref_has_distinct_resource_error(self):
        self.client.errors["branch_head"] = self._api_error(
            "branch_head", APIErrorCategory.NOT_FOUND, status_code=404
        )
        with self.assertRaises(SourceResourceNotFound):
            self._resolve()

    def test_default_branch_must_resolve_to_full_sha(self):
        self.client.get_branch_head_sha = lambda branch: "short-sha"
        with self.assertRaises(SourceContractFailure):
            self._resolve()

    def test_commit_is_fetched_by_pin_and_must_match_response_identity(self):
        self.client.commits[COMMIT_SHA] = CommitMetadata(
            ADVANCED_COMMIT_SHA, ROOT_TREE_SHA
        )
        with self.assertRaises(SourceIdentityMismatch):
            self._resolve()
        self.assertIn(("commit", COMMIT_SHA), self.client.calls)

    def test_malformed_commit_tree_sha_is_rejected(self):
        self.client.commits[COMMIT_SHA] = CommitMetadata(COMMIT_SHA, "not-a-sha")
        with self.assertRaises(SourceContractFailure):
            self._resolve()

    def test_missing_commit_is_distinct_resource_error(self):
        self.client.errors["commit"] = self._api_error(
            "commit", APIErrorCategory.NOT_FOUND, status_code=404
        )
        with self.assertRaises(SourceResourceNotFound):
            self._resolve()

    def test_commit_metadata_retry_preserves_original_branch_head_pin(self):
        pin = self._pin()
        self.assertEqual(pin.repository.commit_sha, COMMIT_SHA)

        self.client.errors["commit"] = self._api_error(
            "commit", APIErrorCategory.TRANSIENT
        )
        with self.assertRaises(SourceTransientFailure):
            verify_pinned_commit(pin)

        self.client.branch_head_sha = ADVANCED_COMMIT_SHA
        del self.client.errors["commit"]
        self.client.commits[COMMIT_SHA] = CommitMetadata(
            COMMIT_SHA, ROOT_TREE_SHA
        )
        resolved = verify_pinned_commit(pin)

        self.assertEqual(resolved.repository.commit_sha, COMMIT_SHA)
        self.assertEqual(resolved.tree_sha, ROOT_TREE_SHA)
        self.assertEqual(self.client.branch_head_calls, 1)
        self.assertEqual(self.client.commit_calls, [COMMIT_SHA, COMMIT_SHA])
        self.assertNotIn(ADVANCED_COMMIT_SHA, self.client.commit_calls)

    def test_tree_is_traversed_nonrecursively_from_pinned_tree_sha(self):
        resolved = self._resolve()
        tree = enumerate_tree(resolved)

        self.assertEqual(
            [entry.path for entry in tree.entries],
            [
                ".portfolio",
                ".portfolio/updates",
                ".portfolio/updates/example-update",
                ".portfolio/updates/example-update/candidate-001.json",
            ],
        )
        self.assertEqual(
            self.client.tree_calls,
            [
                (ROOT_TREE_SHA, False),
                (PORTFOLIO_TREE_SHA, False),
                (UPDATES_TREE_SHA, False),
                (UPDATE_TREE_SHA, False),
            ],
        )

    def test_truncated_or_incomplete_tree_fails_closed(self):
        self.client.trees[ROOT_TREE_SHA] = TreeResponse(
            ROOT_TREE_SHA, (), True
        )
        with self.assertRaises(SourceIncompleteTree):
            enumerate_tree(self._resolve())

    def test_nested_tree_truncation_fails_without_returning_partial_tree(self):
        self.client.trees[PORTFOLIO_TREE_SHA] = TreeResponse(
            PORTFOLIO_TREE_SHA,
            (TreeEntry("updates", "040000", "tree", UPDATES_TREE_SHA),),
            True,
        )
        resolved = self._resolve()
        partial_tree = None

        with self.assertRaises(SourceIncompleteTree):
            partial_tree = enumerate_tree(resolved)

        self.assertIsNone(partial_tree)
        self.assertEqual(
            self.client.tree_calls,
            [(ROOT_TREE_SHA, False), (PORTFOLIO_TREE_SHA, False)],
        )

    def test_tree_identity_mismatch_fails_closed(self):
        self.client.trees[ROOT_TREE_SHA] = TreeResponse("f" * 40, (), False)
        with self.assertRaises(SourceIdentityMismatch):
            enumerate_tree(self._resolve())

    def test_malformed_tree_identity_and_truncation_metadata_are_contract_failures(self):
        malformed_responses = (
            TreeResponse(None, (), False),
            TreeResponse("not-a-sha", (), False),
            TreeResponse("a" * 39, (), False),
            TreeResponse(ROOT_TREE_SHA, (), None),
            TreeResponse(ROOT_TREE_SHA, (), 0),
            TreeResponse(ROOT_TREE_SHA, (), "false"),
        )
        for response in malformed_responses:
            with self.subTest(response=response):
                self.client = FakeGitHubClient()
                self.client.trees[ROOT_TREE_SHA] = response
                with self.assertRaises(SourceContractFailure):
                    enumerate_tree(self._resolve())

    def test_genuine_tree_truncation_remains_incomplete_tree_failure(self):
        self.client.trees[ROOT_TREE_SHA] = TreeResponse(ROOT_TREE_SHA, (), True)
        with self.assertRaises(SourceIncompleteTree):
            enumerate_tree(self._resolve())

    def test_missing_tree_is_distinct_resource_error(self):
        self.client.errors["tree"] = self._api_error(
            "tree", APIErrorCategory.NOT_FOUND, status_code=404
        )
        with self.assertRaises(SourceResourceNotFound):
            enumerate_tree(self._resolve())

    def test_malformed_tree_entry_and_duplicate_paths_fail_closed(self):
        self.client.trees[ROOT_TREE_SHA] = TreeResponse(
            ROOT_TREE_SHA,
            (TreeEntry("bad/name", "040000", "tree", PORTFOLIO_TREE_SHA),),
            False,
        )
        with self.assertRaises(SourceContractFailure):
            enumerate_tree(self._resolve())

        self.client = FakeGitHubClient()
        self.client.trees[ROOT_TREE_SHA] = TreeResponse(
            ROOT_TREE_SHA,
            (
                TreeEntry("same", "100644", "blob", "1" * 40, 1),
                TreeEntry("same", "100644", "blob", "2" * 40, 1),
            ),
            False,
        )
        with self.assertRaises(SourceIdentityMismatch):
            enumerate_tree(self._resolve())

    def test_tree_cycle_fails_closed(self):
        self.client.trees[ROOT_TREE_SHA] = TreeResponse(
            ROOT_TREE_SHA,
            (TreeEntry("loop", "040000", "tree", ROOT_TREE_SHA),),
            False,
        )
        with self.assertRaises(SourceIdentityMismatch):
            enumerate_tree(self._resolve())

    def test_read_blob_returns_exact_bytes_and_checks_tree_membership(self):
        resolved = self._resolve()
        tree = enumerate_tree(resolved)
        candidate_entry = tree.entries[-1]

        self.assertEqual(read_pinned_blob(resolved, tree, candidate_entry), self.client.content)
        self.assertEqual(self.client.blob_calls, [candidate_entry.sha])

        fabricated = TreeEntry(
            candidate_entry.path,
            candidate_entry.mode,
            candidate_entry.type,
            "f" * 40,
            candidate_entry.size,
        )
        with self.assertRaises(SourceContractFailure):
            read_pinned_blob(resolved, tree, fabricated)

    def test_blob_sha_size_and_bytes_are_verified(self):
        resolved = self._resolve()
        tree = enumerate_tree(resolved)
        entry = tree.entries[-1]

        self.client.blob = BlobMetadata("f" * 40, len(self.client.content), self.client.content)
        with self.assertRaises(SourceIdentityMismatch):
            read_pinned_blob(resolved, tree, entry)

        self.client = FakeGitHubClient()
        resolved = self._resolve()
        tree = enumerate_tree(resolved)
        entry = tree.entries[-1]
        self.client.blob = BlobMetadata(entry.sha, len(self.client.content) + 1, self.client.content)
        with self.assertRaises(SourceIdentityMismatch):
            read_pinned_blob(resolved, tree, entry)

        self.client.blob = BlobMetadata(entry.sha, len(self.client.content), b"different bytes")
        with self.assertRaises(SourceIdentityMismatch):
            read_pinned_blob(resolved, tree, entry)

    def test_missing_blob_is_distinct_resource_error(self):
        resolved = self._resolve()
        tree = enumerate_tree(resolved)
        self.client.errors["blob"] = self._api_error(
            "blob", APIErrorCategory.NOT_FOUND, status_code=404
        )
        with self.assertRaises(SourceResourceNotFound):
            read_pinned_blob(resolved, tree, tree.entries[-1])

    def test_symlink_blob_is_not_returned_as_regular_file(self):
        resolved = self._resolve()
        tree = enumerate_tree(resolved)
        symlink = TreeEntry(
            "candidate.json", "120000", "blob", tree.entries[-1].sha, len(self.client.content)
        )
        tree_with_symlink = type(tree)(
            repository=tree.repository,
            tree_sha=tree.tree_sha,
            entries=tree.entries + (symlink,),
        )
        with self.assertRaises(SourceContractFailure):
            read_pinned_blob(resolved, tree_with_symlink, symlink)
        self.assertEqual(self.client.blob_calls, [])

    def test_tree_retry_reuses_pinned_commit_without_resolving_branch_again(self):
        resolved = self._resolve()
        self.client.errors["tree"] = self._api_error(
            "tree", APIErrorCategory.TRANSIENT
        )
        with self.assertRaises(SourceTransientFailure):
            enumerate_tree(resolved)

        del self.client.errors["tree"]
        enumerate_tree(resolved)
        self.assertEqual(self.client.branch_head_calls, 1)
        self.assertEqual(self.client.tree_calls[0][0], ROOT_TREE_SHA)
        self.assertEqual(self.client.tree_calls[-1][0], UPDATE_TREE_SHA)

    def test_blob_failure_never_falls_back_to_branch_file_read(self):
        resolved = self._resolve()
        tree = enumerate_tree(resolved)
        candidate_entry = tree.entries[-1]
        self.client.errors["blob"] = self._api_error(
            "blob", APIErrorCategory.TRANSIENT
        )

        with self.assertRaises(SourceTransientFailure):
            read_pinned_blob(resolved, tree, candidate_entry)

        self.assertEqual(self.client.branch_head_calls, 1)
        self.assertFalse(any(call[0] == "branch_file" for call in self.client.calls))

    def test_api_failures_map_to_distinct_stable_categories(self):
        cases = (
            (APIErrorCategory.AUTHORIZATION, SourceAuthorizationFailure),
            (APIErrorCategory.RATE_LIMITED, SourceRateLimited),
            (APIErrorCategory.TRANSIENT, SourceTransientFailure),
        )
        for category, expected_error in cases:
            with self.subTest(category=category):
                self.client = FakeGitHubClient()
                self.client.errors["repository"] = self._api_error(
                    "repository",
                    category,
                    status_code=403 if category is not APIErrorCategory.TRANSIENT else 503,
                    retry_after_seconds=12 if category is APIErrorCategory.RATE_LIMITED else None,
                )
                with self.assertRaises(expected_error) as raised:
                    self._resolve()
                self.assertEqual(raised.exception.endpoint, "repository")
                if category is APIErrorCategory.RATE_LIMITED:
                    self.assertEqual(raised.exception.retry_after_seconds, 12)

    def test_api_error_with_wrong_endpoint_context_is_contract_failure(self):
        self.client.errors["repository"] = self._api_error(
            "blob", APIErrorCategory.NOT_FOUND
        )
        with self.assertRaises(SourceContractFailure):
            self._resolve()

    def test_error_messages_do_not_include_api_response_body(self):
        error = GitHubAPIError(
            "repository", APIErrorCategory.TRANSIENT
        )
        error.args = ("secret-token and candidate-content",)
        self.client.errors["repository"] = error
        with self.assertRaises(SourceTransientFailure) as raised:
            self._resolve()
        self.assertNotIn("secret-token", str(raised.exception))
        self.assertNotIn("candidate-content", str(raised.exception))

    def test_api_error_string_sanitizes_unknown_endpoint_values(self):
        safe_error = GitHubAPIError("repository", APIErrorCategory.TRANSIENT)
        self.assertEqual(
            str(safe_error), "GitHub API transient failure at repository"
        )
        self.assertEqual(safe_error.endpoint, "repository")

        unsafe_endpoints = (
            "https://user:secret-token@example.test/?candidate=private-content",
            "token=secret-token candidate=private-content",
            None,
            object(),
        )
        for endpoint in unsafe_endpoints:
            with self.subTest(endpoint_type=type(endpoint).__name__):
                error = GitHubAPIError(endpoint, APIErrorCategory.TRANSIENT)
                self.assertIsNone(error.endpoint)
                self.assertEqual(
                    str(error), "GitHub API transient failure at unknown endpoint"
                )
                self.assertNotIn("secret-token", str(error))
                self.assertNotIn("private-content", str(error))


if __name__ == "__main__":
    unittest.main()
