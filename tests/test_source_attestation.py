import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "portfolio-data" / "scripts"))

from source_attestation import (  # noqa: E402
    AttestationOperationalError, AttestationRejected, AttestorAuthorization,
    ChangedFile, CompleteListing, PullRequestMetadata, PullRequestReview,
    TrustedAttestorRegistry, verify_source_attestation,
)
from trusted_source import BlobMetadata, CommitMetadata, TreeEntry, TreeResponse  # noqa: E402


HEAD, MERGE, CURRENT, OTHER = "a" * 40, "b" * 40, "c" * 40, "d" * 40
BODY = b'{"candidate":"private"}'


def blob_sha(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


class FakePRClient:
    def __init__(self):
        self.pr = PullRequestMetadata(100, 200, 7, "main", HEAD, True, MERGE)
        self.reviews = CompleteListing((PullRequestReview(300, 400, "APPROVED", HEAD, 1),), True)
        self.files = CompleteListing((ChangedFile("candidate.json"),), True)
        self.error = None

    def _raise(self):
        if self.error:
            raise RuntimeError("secret-token " + self.error)

    def get_pull_request(self, repository_id, number):
        self._raise()
        return self.pr

    def list_reviews(self, repository_id, number):
        self._raise()
        return self.reviews

    def list_changed_files(self, repository_id, number):
        self._raise()
        return self.files


class FakeContentsClient:
    repository_id = 100
    installation_id = 500
    contents_permission = "read"

    def __init__(self):
        self.branch_sha = CURRENT
        self.branch_calls = []
        self.read_refs = []
        self.contents = {HEAD: BODY, MERGE: BODY, CURRENT: BODY, OTHER: b"old"}
        self.malformed_branch = False
        self.incomplete = False

    def get_branch_head_sha(self, branch):
        self.branch_calls.append(branch)
        return {"bad": "sha"} if self.malformed_branch else self.branch_sha

    def get_commit(self, sha):
        return CommitMetadata(sha, "e" * 40)

    def get_tree(self, sha, *, recursive=False):
        if self.incomplete:
            return TreeResponse(sha, (), True)
        raw = self.contents[self._active_sha]
        digest = blob_sha(raw)
        return TreeResponse(sha, (TreeEntry("candidate.json", "100644", "blob", digest, len(raw)),), False)

    @property
    def _active_sha(self):
        return self.read_refs[-1]

    def get_blob(self, sha):
        raw = self.contents[self._active_sha]
        self.blob = BlobMetadata(sha, len(raw), raw)
        return self.blob

    # Track the target commit before its tree read. This is the existing Contents protocol.
    def activate(self, sha):
        self.read_refs.append(sha)


class SourceAttestationTests(unittest.TestCase):
    def setUp(self):
        self.registry = TrustedAttestorRegistry("registry-v1", 100, "main", (AttestorAuthorization(400),))
        self.client = FakePRClient()
        self.contents = FakeContentsClient()
        # Instrument commit access to associate following tree/blob calls with a SHA.
        original_get_commit = self.contents.get_commit
        def get_commit(sha):
            self.contents.activate(sha)
            return original_get_commit(sha)
        self.contents.get_commit = get_commit

    def verify(self):
        return verify_source_attestation(self.registry, self.client, self.contents,
                                         pull_request_number=7, candidate_path="candidate.json")

    def test_authorized_approval_binds_all_required_evidence(self):
        result = self.verify()
        self.assertEqual((result.repository_id, result.pull_request_id, result.pull_request_number), (100, 200, 7))
        self.assertEqual((result.reviewer_id, result.review_id), (400, 300))
        self.assertEqual(result.reviewed_head_sha, HEAD)
        self.assertEqual(result.candidate_raw_sha256, hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result.merge_commit_sha, MERGE)
        self.assertEqual(result.default_branch_observation_sha, CURRENT)
        self.assertEqual(result.attestor_registry_digest, self.registry.digest)
        self.assertEqual(result.attestor_registry_version, "registry-v1")
        self.assertEqual(result.verifier_policy_version, "1")

    def test_pr_client_never_reads_content_and_contents_client_reads_all_refs(self):
        self.verify()
        self.assertFalse(hasattr(self.client, "read_candidate"))
        self.assertEqual(self.contents.read_refs, [HEAD, MERGE, CURRENT])

    def test_default_branch_resolves_once_and_is_then_read_by_sha(self):
        self.verify()
        self.assertEqual(self.contents.branch_calls, ["main"])
        self.assertNotIn("main", self.contents.read_refs)

    def test_moving_branch_cannot_change_observation_after_pin(self):
        original = self.contents.get_branch_head_sha
        def move_after_pin(branch):
            sha = original(branch)
            self.contents.branch_sha = OTHER
            return sha
        self.contents.get_branch_head_sha = move_after_pin
        result = self.verify()
        self.assertEqual(result.default_branch_observation_sha, CURRENT)
        self.assertEqual(self.contents.read_refs[-1], CURRENT)

    def test_unauthorized_reviewer_rejected(self):
        self.client.reviews = CompleteListing((PullRequestReview(301, 999, "APPROVED", HEAD, 1),), True)
        with self.assertRaises(AttestationRejected): self.verify()

    def test_non_approved_review_rejected(self):
        self.client.reviews = CompleteListing((PullRequestReview(301, 400, "COMMENTED", HEAD, 1),), True)
        with self.assertRaises(AttestationRejected): self.verify()

    def test_stale_approval_rejected(self):
        self.client.reviews = CompleteListing((PullRequestReview(301, 400, "APPROVED", OTHER, 1),), True)
        with self.assertRaises(AttestationRejected): self.verify()

    def test_successive_approval_then_later_change_request_rejected(self):
        self.client.reviews = CompleteListing((
            PullRequestReview(301, 400, "APPROVED", HEAD, 1),
            PullRequestReview(302, 400, "CHANGES_REQUESTED", HEAD, 2),
        ), True)
        with self.assertRaises(AttestationRejected): self.verify()

    def test_successive_stale_then_current_approval_accepted(self):
        self.client.reviews = CompleteListing((
            PullRequestReview(301, 400, "APPROVED", OTHER, 1),
            PullRequestReview(302, 400, "APPROVED", HEAD, 2),
        ), True)
        self.assertEqual(self.verify().review_id, 302)

    def test_conflicting_review_history_order_is_rejected(self):
        self.client.reviews = CompleteListing((
            PullRequestReview(301, 400, "APPROVED", HEAD, 2),
            PullRequestReview(302, 400, "DISMISSED", HEAD, 2),
        ), True)
        with self.assertRaises(AttestationRejected): self.verify()

    def test_unmerged_wrong_base_or_repository_rejected(self):
        cases = (PullRequestMetadata(100, 200, 7, "main", HEAD, False, MERGE),
                 PullRequestMetadata(100, 200, 7, "develop", HEAD, True, MERGE),
                 PullRequestMetadata(101, 200, 7, "main", HEAD, True, MERGE))
        for pr in cases:
            self.client.pr = pr
            with self.subTest(pr=pr), self.assertRaises(AttestationRejected): self.verify()

    def test_unrelated_or_multiple_changed_files_rejected(self):
        for paths in (("other.json",), ("candidate.json", "other.json")):
            self.client.files = CompleteListing(tuple(ChangedFile(p) for p in paths), True)
            with self.subTest(paths=paths), self.assertRaises(AttestationRejected): self.verify()

    def test_missing_candidate_or_incomplete_contents_tree_is_operational(self):
        self.contents.contents.pop(HEAD)
        with self.assertRaises(AttestationOperationalError): self.verify()
        self.setUp()
        self.contents.incomplete = True
        with self.assertRaises(AttestationOperationalError): self.verify()

    def test_missing_or_malformed_default_branch_pin_is_operational(self):
        self.contents.branch_sha = None
        with self.assertRaises(AttestationOperationalError): self.verify()
        self.setUp()
        self.contents.malformed_branch = True
        with self.assertRaises(AttestationOperationalError): self.verify()

    def test_incomplete_review_and_file_pagination_is_operational(self):
        self.client.reviews = CompleteListing(self.client.reviews.items, False)
        with self.assertRaises(AttestationOperationalError): self.verify()
        self.setUp()
        self.client.files = CompleteListing(self.client.files.items, False)
        with self.assertRaises(AttestationOperationalError): self.verify()

    def test_malformed_api_responses_and_api_errors_are_operational_and_sanitized(self):
        self.client.pr = {"secret": "payload"}
        with self.assertRaises(AttestationOperationalError): self.verify()
        self.setUp()
        self.client.error = "candidate-private review-body-secret token-secret"
        with self.assertRaises(AttestationOperationalError) as raised: self.verify()
        for secret in ("candidate-private", "review-body-secret", "token-secret"):
            self.assertNotIn(secret, str(raised.exception))

    def test_missing_or_invalid_registry_rejected(self):
        with self.assertRaises(AttestationRejected):
            verify_source_attestation(None, self.client, self.contents, pull_request_number=7, candidate_path="candidate.json")
        with self.assertRaises(ValueError): TrustedAttestorRegistry("v1", 100, "main", ())
        with self.assertRaises(ValueError): AttestorAuthorization(True)

    def test_byte_mismatch_rejected(self):
        self.contents.contents[CURRENT] = b"different"
        with self.assertRaises(AttestationRejected): self.verify()

    def test_failure_messages_do_not_expose_payloads(self):
        self.client.error = "candidate-secret review-body-secret token-secret"
        with self.assertRaises(AttestationOperationalError) as raised: self.verify()
        self.assertNotIn("secret-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
