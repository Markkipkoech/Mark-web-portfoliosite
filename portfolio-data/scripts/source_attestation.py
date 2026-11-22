"""Verify source-owner review attestations using injected read-only clients.

No transport, credentials, candidate parsing, or workflow integration is provided.
"""

from dataclasses import dataclass
import hashlib
import re
from typing import Protocol, Tuple

from trusted_source import (
    BlobMetadata,
    CommitMetadata,
    RepositoryContentsClient,
    TreeResponse,
)


VERIFIER_POLICY_VERSION = "1"
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class AttestationError(Exception):
    """Sanitized verification failure; messages never include API payloads."""


class AttestationOperationalError(AttestationError):
    """API outage, incomplete listing, rate limit, or malformed API response."""


class AttestationRejected(AttestationError):
    """Evidence does not satisfy the attestation policy."""


def _positive_id(value: object) -> bool:
    return type(value) is int and value > 0


def _safe_text(value: object) -> bool:
    return (isinstance(value, str) and bool(value) and value.strip() == value
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


@dataclass(frozen=True)
class AttestorAuthorization:
    reviewer_id: int

    def __post_init__(self):
        if not _positive_id(self.reviewer_id):
            raise ValueError("attestor reviewer ID must be positive")


@dataclass(frozen=True)
class TrustedAttestorRegistry:
    version: str
    repository_id: int
    default_branch: str
    attestors: Tuple[AttestorAuthorization, ...]

    def __post_init__(self):
        if not _safe_text(self.version) or not _positive_id(self.repository_id):
            raise ValueError("attestor registry identity is invalid")
        if not _safe_text(self.default_branch) or "/" in self.default_branch:
            raise ValueError("attestor registry default branch is invalid")
        if (not isinstance(self.attestors, tuple) or not self.attestors
                or any(not isinstance(a, AttestorAuthorization) for a in self.attestors)
                or len({a.reviewer_id for a in self.attestors}) != len(self.attestors)):
            raise ValueError("attestor registry entries are invalid")

    @property
    def digest(self) -> str:
        # Canonical unambiguous serialization of this repository's registry entry.
        payload = "\n".join((self.version, str(self.repository_id), self.default_branch,
                             *(str(a.reviewer_id) for a in sorted(self.attestors, key=lambda x: x.reviewer_id))))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PullRequestMetadata:
    repository_id: int
    pull_request_id: int
    number: int
    base_branch: str
    head_sha: str
    merged: bool
    merge_commit_sha: str

    def __post_init__(self):
        if not all(_positive_id(v) for v in (self.repository_id, self.pull_request_id, self.number)):
            raise ValueError("pull request identity is invalid")
        if not _safe_text(self.base_branch) or not isinstance(self.merged, bool):
            raise ValueError("pull request metadata is invalid")
        if not isinstance(self.head_sha, str) or not _SHA.fullmatch(self.head_sha):
            raise ValueError("pull request head SHA is invalid")
        if not isinstance(self.merge_commit_sha, str) or not _SHA.fullmatch(self.merge_commit_sha):
            raise ValueError("pull request merge SHA is invalid")


@dataclass(frozen=True)
class PullRequestReview:
    review_id: int
    reviewer_id: int
    state: str
    commit_id: str
    submitted_at: int

    def __post_init__(self):
        if not _positive_id(self.review_id) or not _positive_id(self.reviewer_id):
            raise ValueError("review identity is invalid")
        if self.state not in ("APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"):
            raise ValueError("review state is invalid")
        if not isinstance(self.commit_id, str) or not _SHA.fullmatch(self.commit_id):
            raise ValueError("review commit SHA is invalid")
        if not _positive_id(self.submitted_at):
            raise ValueError("review ordering value is invalid")


@dataclass(frozen=True)
class ChangedFile:
    path: str

    def __post_init__(self):
        if (not _safe_text(self.path) or self.path.startswith("/") or "\\" in self.path
                or any(part in ("", ".", "..") for part in self.path.split("/"))):
            raise ValueError("changed file path is invalid")


@dataclass(frozen=True)
class CompleteListing:
    items: Tuple[object, ...]
    complete: bool

    def __post_init__(self):
        if not isinstance(self.items, tuple) or not isinstance(self.complete, bool):
            raise ValueError("listing response is invalid")


class PullRequestsReadClient(Protocol):
    """Injected client limited to Pull Requests metadata and listings."""
    def get_pull_request(self, repository_id: int, number: int) -> PullRequestMetadata: ...
    def list_reviews(self, repository_id: int, number: int) -> CompleteListing: ...
    def list_changed_files(self, repository_id: int, number: int) -> CompleteListing: ...


@dataclass(frozen=True)
class VerificationResult:
    repository_id: int
    pull_request_id: int
    pull_request_number: int
    reviewer_id: int
    review_id: int
    reviewed_head_sha: str
    candidate_path: str
    candidate_raw_sha256: str
    merge_commit_sha: str
    default_branch_observation_sha: str
    attestor_registry_version: str
    attestor_registry_digest: str
    verifier_policy_version: str


def _read_candidate_at_sha(client: RepositoryContentsClient, repository_id: int,
                           commit_sha: str, path: str) -> bytes:
    """Resolve one exact regular blob through the existing Contents read protocol."""
    commit = client.get_commit(commit_sha)
    if not isinstance(commit, CommitMetadata) or commit.commit_sha != commit_sha or not _SHA.fullmatch(commit.tree_sha):
        raise AttestationOperationalError("pinned commit response is malformed")
    parts = path.split("/")
    tree_sha = commit.tree_sha
    for part in parts[:-1]:
        response = client.get_tree(tree_sha, recursive=False)
        if not isinstance(response, TreeResponse) or response.tree_sha != tree_sha or response.truncated is not False:
            raise AttestationOperationalError("pinned tree response is malformed or incomplete")
        matches = [entry for entry in response.entries if entry.path == part]
        if len(matches) != 1 or matches[0].type != "tree" or matches[0].mode != "040000" or not _SHA.fullmatch(matches[0].sha):
            raise AttestationOperationalError("candidate path is missing or ambiguous")
        tree_sha = matches[0].sha
    response = client.get_tree(tree_sha, recursive=False)
    if not isinstance(response, TreeResponse) or response.tree_sha != tree_sha or response.truncated is not False:
        raise AttestationOperationalError("pinned tree response is malformed or incomplete")
    matches = [entry for entry in response.entries if entry.path == parts[-1]]
    if len(matches) != 1 or matches[0].type != "blob" or matches[0].mode not in ("100644", "100755") or not _SHA.fullmatch(matches[0].sha):
        raise AttestationOperationalError("candidate path is missing or ambiguous")
    blob = client.get_blob(matches[0].sha)
    if not isinstance(blob, BlobMetadata) or blob.blob_sha != matches[0].sha or not isinstance(blob.content, bytes) or type(blob.size) is not int or blob.size != len(blob.content):
        raise AttestationOperationalError("candidate blob response is malformed")
    hash_name = "sha1" if len(matches[0].sha) == 40 else "sha256"
    git_blob = hashlib.new(hash_name, b"blob " + str(len(blob.content)).encode("ascii") + b"\0" + blob.content).hexdigest()
    if git_blob != matches[0].sha:
        raise AttestationOperationalError("candidate blob identity is inconsistent")
    return blob.content


def verify_source_attestation(registry: TrustedAttestorRegistry,
                              client: PullRequestsReadClient,
                              contents_client: RepositoryContentsClient, *,
                              pull_request_number: int, candidate_path: str) -> VerificationResult:
    """Verify a merged PR and return a digest-bound, immutable attestation."""
    if not isinstance(registry, TrustedAttestorRegistry):
        raise AttestationRejected("trusted attestor registry is required")
    if any(not callable(getattr(client, method, None)) for method in (
            "get_pull_request", "list_reviews", "list_changed_files")):
        raise AttestationOperationalError("Pull Requests read client is malformed")
    if any(not callable(getattr(contents_client, method, None)) for method in (
            "get_branch_head_sha", "get_commit", "get_tree", "get_blob")):
        raise AttestationOperationalError("Contents read client is malformed")
    if getattr(contents_client, "repository_id", None) != registry.repository_id or getattr(contents_client, "contents_permission", None) != "read":
        raise AttestationOperationalError("Contents read client identity is inconsistent")
    if not _positive_id(pull_request_number):
        raise AttestationRejected("pull request number is invalid")
    try:
        ChangedFile(candidate_path)
        pr = client.get_pull_request(registry.repository_id, pull_request_number)
        if not isinstance(pr, PullRequestMetadata):
            raise AttestationOperationalError("pull request response is malformed")
        if pr.repository_id != registry.repository_id or pr.number != pull_request_number:
            raise AttestationRejected("pull request repository identity does not match")
        if pr.base_branch != registry.default_branch:
            raise AttestationRejected("pull request base branch is not registered")
        if not pr.merged:
            raise AttestationRejected("pull request is not merged")
        reviews = client.list_reviews(registry.repository_id, pull_request_number)
        files = client.list_changed_files(registry.repository_id, pull_request_number)
        for listing in (reviews, files):
            if not isinstance(listing, CompleteListing):
                raise AttestationOperationalError("Pull Requests listing is malformed")
            if not listing.complete:
                raise AttestationOperationalError("Pull Requests listing is incomplete")
        if any(not isinstance(review, PullRequestReview) for review in reviews.items):
            raise AttestationOperationalError("review response is malformed")
        if any(not isinstance(item, ChangedFile) for item in files.items):
            raise AttestationOperationalError("changed-file response is malformed")
        if len({r.review_id for r in reviews.items}) != len(reviews.items):
            raise AttestationOperationalError("review response contains conflicting entries")
        registered_ids = {a.reviewer_id for a in registry.attestors}
        if len(files.items) != 1 or files.items[0].path != candidate_path:
            raise AttestationRejected("pull request changed files outside the candidate")
        authorized = [r for r in reviews.items if r.reviewer_id in registered_ids]
        if len({(r.reviewer_id, r.submitted_at) for r in authorized}) != len(authorized):
            raise AttestationRejected("authorized review history is conflicting or ambiguous")
        latest_by_reviewer = {}
        for review in authorized:
            previous = latest_by_reviewer.get(review.reviewer_id)
            if previous is None or review.submitted_at > previous.submitted_at:
                latest_by_reviewer[review.reviewer_id] = review
        if any(r.state in ("DISMISSED", "CHANGES_REQUESTED") for r in latest_by_reviewer.values()):
            raise AttestationRejected("authorized review history contains an applicable block")
        applicable = [r for r in latest_by_reviewer.values() if r.state == "APPROVED" and r.commit_id == pr.head_sha]
        if not applicable:
            raise AttestationRejected("no authorized approval matches the reviewed head")
        if len(applicable) != 1:
            raise AttestationRejected("authorized approval evidence is ambiguous")
        branch_sha = contents_client.get_branch_head_sha(registry.default_branch)
        if not isinstance(branch_sha, str) or not _SHA.fullmatch(branch_sha):
            raise AttestationOperationalError("default branch head response is malformed")
        reviewed = _read_candidate_at_sha(contents_client, registry.repository_id, pr.head_sha, candidate_path)
        merged = _read_candidate_at_sha(contents_client, registry.repository_id, pr.merge_commit_sha, candidate_path)
        current = _read_candidate_at_sha(contents_client, registry.repository_id, branch_sha, candidate_path)
        if not all(isinstance(raw, bytes) for raw in (reviewed, merged, current)):
            raise AttestationOperationalError("candidate byte response is malformed")
        if reviewed != merged or reviewed != current:
            raise AttestationRejected("candidate bytes differ across reviewed and merged refs")
        review = applicable[0]
        return VerificationResult(registry.repository_id, pr.pull_request_id, pr.number,
                                  review.reviewer_id, review.review_id, pr.head_sha,
                                  candidate_path, hashlib.sha256(reviewed).hexdigest(),
                                  pr.merge_commit_sha, branch_sha, registry.version, registry.digest,
                                  VERIFIER_POLICY_VERSION)
    except AttestationError:
        raise
    except Exception:
        # Adapter exceptions may contain response bodies, paths, tokens, or payloads.
        raise AttestationOperationalError("Pull Requests API operation failed") from None
