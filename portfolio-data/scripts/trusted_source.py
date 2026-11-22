"""Resolve trusted, commit-pinned source data through an injected GitHub client.

This module contains no HTTP implementation, credentials, or live GitHub access.
The injected App client must implement the protocols below and translate API
failures into :class:`GitHubAPIError` with symbolic endpoint context. Repository
and tree reads after resolution use only the repository-scoped client and pinned
object IDs; no branch-based file-read method is part of that interface.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import re
from typing import Mapping, Optional, Protocol, Sequence, Tuple


_PERMITTED_API_ENDPOINTS = frozenset(
    {
        "repository",
        "repository_installation",
        "installation_repositories",
        "scoped_client",
        "branch_head",
        "commit",
        "tree",
        "blob",
    }
)


class APIErrorCategory(str, Enum):
    """Normalized failure categories supplied by the injected API adapter."""

    NOT_FOUND = "not_found"
    AUTHORIZATION = "authorization"
    RATE_LIMITED = "rate_limited"
    TRANSIENT = "transient"


class GitHubAPIError(Exception):
    """Sanitized API failure with endpoint context and no response body.

    The adapter must classify rate limits separately from authorization errors,
    including 403 responses, and must use a symbolic endpoint name such as
    ``repository``, ``repository_installation``, ``installation_repositories``,
    ``scoped_client``, ``branch_head``, ``commit``, ``tree``, or ``blob``.
    A not-found response for either installation endpoint must retain that
    context because GitHub may conceal authorization failures as not-found.
    """

    def __init__(
        self,
        endpoint: object,
        category: APIErrorCategory,
        *,
        status_code: Optional[int] = None,
        retry_after_seconds: Optional[float] = None,
    ) -> None:
        if not isinstance(category, APIErrorCategory):
            raise ValueError("category must be an APIErrorCategory")
        safe_endpoint = (
            endpoint
            if isinstance(endpoint, str) and endpoint in _PERMITTED_API_ENDPOINTS
            else None
        )
        self.endpoint = safe_endpoint
        self.category = category
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds
        # Never include response bodies, tokens, or candidate data in this text.
        endpoint_label = safe_endpoint or "unknown endpoint"
        super().__init__(
            "GitHub API {} failure at {}".format(category.value, endpoint_label)
        )


class SourceResolverError(Exception):
    """Base class for sanitized trusted-source resolver failures."""

    def __init__(
        self,
        message: str,
        *,
        endpoint: Optional[str] = None,
        retry_after_seconds: Optional[float] = None,
    ) -> None:
        self.endpoint = endpoint
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message)


class SourceResourceNotFound(SourceResolverError):
    """A registered repository resource, ref, commit, tree, or blob is absent."""


class SourceAuthorizationFailure(SourceResolverError):
    """The expected App or repository-scoped Contents read is not authorized."""


class SourceRateLimited(SourceResolverError):
    """The API rate limit was reached; retry metadata may be available."""


class SourceTransientFailure(SourceResolverError):
    """A retryable transport or service failure occurred."""


class SourceIdentityMismatch(SourceResolverError):
    """Trusted source identity or an immutable Git object identity conflicts."""


class SourceContractFailure(SourceResolverError):
    """An input or API response is malformed or incomplete for this contract."""


class SourceIncompleteTree(SourceContractFailure):
    """A tree response was explicitly truncated or incomplete."""


@dataclass(frozen=True)
class RegisteredRepository:
    """Owner-approved repository mapping supplied by the central registry."""

    project_id: str
    repository_id: int
    full_name: str


@dataclass(frozen=True)
class RepositoryMetadata:
    """Repository fields returned by trusted GitHub repository metadata."""

    repository_id: int
    full_name: str
    default_branch: str


@dataclass(frozen=True)
class InstallationMetadata:
    """App installation identity and its effective permission declaration."""

    installation_id: int
    app_id: int
    permissions: Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class InstallationRepositories:
    """Complete repository-ID listing for one installation."""

    repository_ids: Tuple[int, ...]
    complete: bool


@dataclass(frozen=True)
class CommitMetadata:
    """Commit and root tree object IDs returned by the Git data API."""

    commit_sha: str
    tree_sha: str


@dataclass(frozen=True)
class TreeEntry:
    """One flattened Git tree entry with a repository-relative POSIX path."""

    path: str
    mode: str
    type: str
    sha: str
    size: Optional[int] = None


@dataclass(frozen=True)
class TreeResponse:
    """One non-recursive tree response from the injected API client."""

    tree_sha: str
    entries: Tuple[TreeEntry, ...]
    truncated: bool


@dataclass(frozen=True)
class BlobMetadata:
    """Blob metadata and its exact decoded content bytes."""

    blob_sha: str
    size: int
    content: bytes


class RepositoryContentsClient(Protocol):
    """Client scoped to exactly one repository and Contents read permission."""

    repository_id: int
    installation_id: int
    contents_permission: str

    def get_branch_head_sha(self, branch: str) -> str:
        """Resolve a branch ref once and return its full commit object ID."""

    def get_commit(self, commit_sha: str) -> CommitMetadata:
        """Fetch commit metadata by the supplied immutable commit SHA."""

    def get_tree(self, tree_sha: str, *, recursive: bool) -> TreeResponse:
        """Fetch tree metadata by SHA; this resolver requests non-recursive trees."""

    def get_blob(self, blob_sha: str) -> BlobMetadata:
        """Fetch blob metadata and bytes by the tree-provided blob SHA."""


class GitHubAppClient(Protocol):
    """App-authenticated metadata client supplied by the caller."""

    def get_repository_by_id(self, repository_id: int) -> RepositoryMetadata:
        """Fetch a repository by its numeric GitHub ID."""

    def get_repository_installation(
        self, repository_id: int
    ) -> InstallationMetadata:
        """Return the App installation associated with this repository."""

    def list_installation_repositories(
        self, installation_id: int
    ) -> InstallationRepositories:
        """Return a fully paginated repository-ID list for this installation."""

    def create_repository_scoped_client(
        self,
        installation_id: int,
        repository_id: int,
        *,
        permissions: Mapping[str, str],
    ) -> RepositoryContentsClient:
        """Create a client scoped to one repository and requested permissions."""


@dataclass(frozen=True)
class PinnedRepository:
    """Repository identity pinned to one default-branch commit SHA."""

    repository_id: int
    full_name: str
    default_branch: str
    commit_sha: str
    installation_id: int


@dataclass(frozen=True)
class PinnedSource:
    """Commit pin checkpoint before commit metadata/tree verification."""

    repository: PinnedRepository
    client: RepositoryContentsClient


@dataclass(frozen=True)
class ResolvedSource:
    """Pinned commit with tree SHA verified against its commit metadata."""

    repository: PinnedRepository
    tree_sha: str
    client: RepositoryContentsClient


@dataclass(frozen=True)
class PinnedTree:
    """Complete flattened tree whose root belongs to a pinned commit."""

    repository: PinnedRepository
    tree_sha: str
    entries: Tuple[TreeEntry, ...]


_FULL_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_INSTALLATION_ENDPOINTS = frozenset(
    {"repository_installation", "installation_repositories"}
)
_BLOB_MODES = frozenset({"100644", "100755", "120000"})
_REGULAR_BLOB_MODES = frozenset({"100644", "100755"})


def registered_repository_from_entry(
    project_id: str, entry: Mapping[str, object]
) -> RegisteredRepository:
    """Build a resolver input from a registry entry without inventing IDs."""
    if not isinstance(project_id, str) or not project_id.strip():
        raise SourceContractFailure("registered project ID is invalid")
    if not isinstance(entry, Mapping):
        raise SourceContractFailure("registered repository entry is invalid")

    repository_id = entry.get("repository_id")
    if type(repository_id) is not int or repository_id <= 0:
        raise SourceContractFailure(
            "registered repository requires an owner-approved positive numeric ID"
        )
    full_name = entry.get("repository")
    if (
        not isinstance(full_name, str)
        or full_name.count("/") != 1
        or any(not part or part.strip() != part for part in full_name.split("/"))
        or any(character.isspace() for character in full_name)
    ):
        raise SourceContractFailure("registered repository name is malformed")
    return RegisteredRepository(project_id, repository_id, full_name)


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _valid_object_id(value: object) -> bool:
    return isinstance(value, str) and _FULL_OBJECT_ID.fullmatch(value) is not None


def _api_call(endpoint: str, operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except GitHubAPIError as error:
        if error.endpoint != endpoint or endpoint not in _PERMITTED_API_ENDPOINTS:
            raise SourceContractFailure(
                "GitHub API client returned inconsistent endpoint context"
            ) from None
        if error.category is APIErrorCategory.NOT_FOUND:
            if endpoint in _INSTALLATION_ENDPOINTS:
                raise SourceAuthorizationFailure(
                    "GitHub App installation is unavailable or concealed",
                    endpoint=endpoint,
                ) from None
            raise SourceResourceNotFound(
                "GitHub source resource was not found", endpoint=endpoint
            ) from None
        if error.category is APIErrorCategory.AUTHORIZATION:
            raise SourceAuthorizationFailure(
                "GitHub App is not authorized for the requested source operation",
                endpoint=endpoint,
            ) from None
        if error.category is APIErrorCategory.RATE_LIMITED:
            retry_after = error.retry_after_seconds
            if retry_after is not None and (
                isinstance(retry_after, bool)
                or not isinstance(retry_after, (int, float))
                or retry_after < 0
            ):
                retry_after = None
            raise SourceRateLimited(
                "GitHub API rate limit reached",
                endpoint=endpoint,
                retry_after_seconds=retry_after,
            ) from None
        if error.category is APIErrorCategory.TRANSIENT:
            raise SourceTransientFailure(
                "temporary GitHub API failure", endpoint=endpoint
            ) from None
        raise SourceContractFailure("GitHub API client returned an unknown failure") from None


def _validate_registered_source(source: RegisteredRepository) -> None:
    if not isinstance(source, RegisteredRepository):
        raise SourceContractFailure("registered source input has the wrong type")
    if not isinstance(source.project_id, str) or not source.project_id.strip():
        raise SourceContractFailure("registered project ID is invalid")
    if not _positive_int(source.repository_id):
        raise SourceContractFailure(
            "registered repository requires an owner-approved positive numeric ID"
        )
    if (
        not isinstance(source.full_name, str)
        or source.full_name.count("/") != 1
        or any(not part or part.strip() != part for part in source.full_name.split("/"))
        or any(character.isspace() for character in source.full_name)
    ):
        raise SourceContractFailure("registered repository name is malformed")


def resolve_registered_source(
    registered: RegisteredRepository,
    app_client: GitHubAppClient,
    *,
    expected_app_id: int,
) -> PinnedSource:
    """Verify registry/App identity and checkpoint one default-branch commit.

    The caller is responsible for validating the complete central registry before
    constructing ``registered``. A missing numeric ID is a contract failure; it
    is never looked up or inferred from repository names. The returned frozen
    value is the retry checkpoint: commit metadata verification is separate, so
    a retry never needs to resolve the branch again.
    """
    _validate_registered_source(registered)
    if not _positive_int(expected_app_id):
        raise SourceContractFailure("expected GitHub App ID must be positive")

    repository = _api_call(
        "repository", app_client.get_repository_by_id, registered.repository_id
    )
    if not isinstance(repository, RepositoryMetadata):
        raise SourceContractFailure("repository metadata response is malformed")
    if not _positive_int(repository.repository_id) or not isinstance(
        repository.full_name, str
    ):
        raise SourceContractFailure("repository metadata response is malformed")
    if repository.repository_id != registered.repository_id:
        raise SourceIdentityMismatch("GitHub repository ID does not match registry")
    if repository.full_name != registered.full_name:
        raise SourceIdentityMismatch(
            "GitHub repository name does not exactly match registry"
        )
    if (
        not isinstance(repository.default_branch, str)
        or not repository.default_branch
        or repository.default_branch.strip() != repository.default_branch
        or any(character.isspace() for character in repository.default_branch)
    ):
        raise SourceContractFailure("repository default branch metadata is malformed")

    installation = _api_call(
        "repository_installation",
        app_client.get_repository_installation,
        registered.repository_id,
    )
    if not isinstance(installation, InstallationMetadata):
        raise SourceContractFailure("App installation metadata is malformed")
    if not _positive_int(installation.installation_id) or not _positive_int(
        installation.app_id
    ):
        raise SourceContractFailure("App installation metadata is malformed")
    if installation.app_id != expected_app_id:
        raise SourceAuthorizationFailure("repository installation belongs to another App")
    if not isinstance(installation.permissions, tuple) or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or not all(isinstance(value, str) for value in pair)
        for pair in installation.permissions
    ):
        raise SourceContractFailure("App installation permissions are malformed")
    permissions = dict(installation.permissions)
    if len(permissions) != len(installation.permissions):
        raise SourceContractFailure("App installation permissions contain duplicates")
    if permissions.get("contents") != "read":
        raise SourceAuthorizationFailure(
            "GitHub App installation does not have Contents read-only access"
        )

    installed_repositories = _api_call(
        "installation_repositories",
        app_client.list_installation_repositories,
        installation.installation_id,
    )
    if not isinstance(installed_repositories, InstallationRepositories):
        raise SourceContractFailure("installation repository listing is malformed")
    if installed_repositories.complete is not True:
        raise SourceContractFailure(
            "installation repository listing is incomplete"
        )
    if not isinstance(installed_repositories.repository_ids, tuple) or any(
        not _positive_int(repository_id)
        for repository_id in installed_repositories.repository_ids
    ):
        raise SourceContractFailure("installation repository listing is malformed")
    if len(set(installed_repositories.repository_ids)) != len(
        installed_repositories.repository_ids
    ):
        raise SourceContractFailure("installation repository listing has duplicates")
    if registered.repository_id not in installed_repositories.repository_ids:
        raise SourceAuthorizationFailure(
            "registered repository is not included in the App installation"
        )

    scoped_client = _api_call(
        "scoped_client",
        app_client.create_repository_scoped_client,
        installation.installation_id,
        registered.repository_id,
        permissions={"contents": "read"},
    )
    if not _is_repository_contents_client(scoped_client):
        raise SourceContractFailure("repository-scoped client is malformed")
    if (
        scoped_client.repository_id != registered.repository_id
        or scoped_client.installation_id != installation.installation_id
    ):
        raise SourceIdentityMismatch(
            "repository-scoped client identity does not match the verified source"
        )
    if scoped_client.contents_permission != "read":
        raise SourceAuthorizationFailure(
            "repository-scoped client is not limited to Contents read access"
        )

    commit_sha = _api_call(
        "branch_head",
        scoped_client.get_branch_head_sha,
        repository.default_branch,
    )
    if not _valid_object_id(commit_sha):
        raise SourceContractFailure("default branch did not resolve to a full commit SHA")

    pinned = PinnedRepository(
        repository_id=registered.repository_id,
        full_name=repository.full_name,
        default_branch=repository.default_branch,
        commit_sha=commit_sha,
        installation_id=installation.installation_id,
    )
    return PinnedSource(repository=pinned, client=scoped_client)


def verify_pinned_commit(source: PinnedSource) -> ResolvedSource:
    """Verify commit metadata using an existing immutable branch-head checkpoint.

    Retry this operation with the same ``PinnedSource`` after a transient API
    failure. It does not resolve the default branch or make a branch-head call.
    A tree SHA is exposed only after the returned commit SHA has been verified.
    """
    if not isinstance(source, PinnedSource) or not isinstance(
        source.repository, PinnedRepository
    ):
        raise SourceContractFailure("pinned source checkpoint is malformed")
    if (
        not _positive_int(source.repository.repository_id)
        or not _positive_int(source.repository.installation_id)
        or not isinstance(source.repository.full_name, str)
        or not source.repository.full_name
        or not isinstance(source.repository.default_branch, str)
        or not source.repository.default_branch
        or not _valid_object_id(source.repository.commit_sha)
    ):
        raise SourceContractFailure("pinned source checkpoint is malformed")
    if not _is_repository_contents_client(source.client):
        raise SourceContractFailure("repository-scoped client is malformed")
    if (
        source.client.repository_id != source.repository.repository_id
        or source.client.installation_id != source.repository.installation_id
        or source.client.contents_permission != "read"
    ):
        raise SourceIdentityMismatch(
            "repository-scoped client no longer matches source checkpoint"
        )

    commit = _api_call(
        "commit", source.client.get_commit, source.repository.commit_sha
    )
    if not isinstance(commit, CommitMetadata):
        raise SourceContractFailure("commit metadata response is malformed")
    if not _valid_object_id(commit.commit_sha) or not _valid_object_id(commit.tree_sha):
        raise SourceContractFailure("commit metadata contains a malformed object SHA")
    if commit.commit_sha != source.repository.commit_sha:
        raise SourceIdentityMismatch("commit response SHA does not match pinned commit")

    return ResolvedSource(
        repository=source.repository,
        tree_sha=commit.tree_sha,
        client=source.client,
    )


def _validate_tree_entry(entry: TreeEntry) -> None:
    if not isinstance(entry, TreeEntry):
        raise SourceContractFailure("tree response contains malformed entry metadata")
    if (
        not isinstance(entry.path, str)
        or not entry.path
        or entry.path in (".", "..")
        or "/" in entry.path
        or "\\" in entry.path
        or "\x00" in entry.path
    ):
        raise SourceContractFailure("tree response contains a malformed path component")
    if not _valid_object_id(entry.sha):
        raise SourceContractFailure("tree entry contains a malformed object SHA")
    if entry.type == "tree":
        if entry.mode != "040000" or entry.size is not None:
            raise SourceContractFailure("tree entry has inconsistent tree metadata")
    elif entry.type == "blob":
        if entry.mode not in _BLOB_MODES:
            raise SourceContractFailure("tree entry has an unsupported blob mode")
        if entry.size is not None and (
            type(entry.size) is not int or entry.size < 0
        ):
            raise SourceContractFailure("tree entry has an invalid blob size")
    elif entry.type == "commit":
        if entry.mode != "160000" or entry.size is not None:
            raise SourceContractFailure("tree entry has inconsistent submodule metadata")
    else:
        raise SourceContractFailure("tree entry has an unsupported Git object type")


def _is_repository_contents_client(client: object) -> bool:
    required_methods = (
        "get_branch_head_sha",
        "get_commit",
        "get_tree",
        "get_blob",
    )
    return (
        _positive_int(getattr(client, "repository_id", None))
        and _positive_int(getattr(client, "installation_id", None))
        and isinstance(getattr(client, "contents_permission", None), str)
        and all(callable(getattr(client, name, None)) for name in required_methods)
    )


def _check_scoped_source(source: ResolvedSource) -> None:
    if not isinstance(source, ResolvedSource) or not isinstance(
        source.repository, PinnedRepository
    ):
        raise SourceContractFailure("resolved source input is malformed")
    if not _is_repository_contents_client(source.client):
        raise SourceContractFailure("repository-scoped client is malformed")
    if (
        not _positive_int(source.repository.repository_id)
        or not _positive_int(source.repository.installation_id)
        or not _valid_object_id(source.repository.commit_sha)
        or not _valid_object_id(source.tree_sha)
    ):
        raise SourceContractFailure("resolved source contains malformed pinned identity")
    if (
        source.client.repository_id != source.repository.repository_id
        or source.client.installation_id != source.repository.installation_id
        or source.client.contents_permission != "read"
    ):
        raise SourceIdentityMismatch("repository-scoped client no longer matches source pin")


def enumerate_tree(source: ResolvedSource) -> PinnedTree:
    """Return a complete tree using only non-recursive, pinned tree-SHA reads.

    Non-recursive traversal avoids silently accepting GitHub's truncated
    recursive-tree responses. If any response is incomplete, the operation fails
    closed. Candidate-specific path and symlink policy is intentionally separate.
    """
    _check_scoped_source(source)
    entries = []
    seen_paths = set()
    pending = [("", source.tree_sha, frozenset())]

    while pending:
        prefix, expected_tree_sha, ancestors = pending.pop()
        if expected_tree_sha in ancestors:
            raise SourceIdentityMismatch("Git tree contains a cyclic tree reference")
        response = _api_call(
            "tree",
            source.client.get_tree,
            expected_tree_sha,
            recursive=False,
        )
        if not isinstance(response, TreeResponse):
            raise SourceContractFailure("tree response is malformed")
        if not _valid_object_id(response.tree_sha):
            raise SourceContractFailure("tree response contains a malformed object SHA")
        if type(response.truncated) is not bool:
            raise SourceContractFailure("tree response truncation metadata is malformed")
        if response.tree_sha != expected_tree_sha:
            raise SourceIdentityMismatch("tree response SHA does not match pinned tree")
        if response.truncated:
            raise SourceIncompleteTree(
                "Git tree enumeration is incomplete or truncated"
            )
        if not isinstance(response.entries, tuple):
            raise SourceContractFailure("tree response entries are malformed")

        next_ancestors = ancestors | {expected_tree_sha}
        for entry in response.entries:
            _validate_tree_entry(entry)
            full_path = "{}/{}".format(prefix, entry.path) if prefix else entry.path
            if full_path in seen_paths:
                raise SourceIdentityMismatch("Git tree contains duplicate paths")
            seen_paths.add(full_path)
            flattened = TreeEntry(
                path=full_path,
                mode=entry.mode,
                type=entry.type,
                sha=entry.sha,
                size=entry.size,
            )
            entries.append(flattened)
            if entry.type == "tree":
                pending.append((full_path, entry.sha, next_ancestors))

    return PinnedTree(
        repository=source.repository,
        tree_sha=source.tree_sha,
        entries=tuple(entries),
    )


def read_pinned_blob(
    source: ResolvedSource, tree: PinnedTree, entry: TreeEntry
) -> bytes:
    """Return exact bytes for a regular blob proven present in the pinned tree."""
    _check_scoped_source(source)
    if (
        not isinstance(tree, PinnedTree)
        or tree.repository != source.repository
        or tree.tree_sha != source.tree_sha
    ):
        raise SourceIdentityMismatch("tree snapshot does not belong to the pinned source")
    if not isinstance(entry, TreeEntry) or entry not in tree.entries:
        raise SourceContractFailure("blob entry was not obtained from the pinned tree")
    if entry.type != "blob" or entry.mode not in _REGULAR_BLOB_MODES:
        raise SourceContractFailure("pinned tree entry is not a regular file blob")

    blob = _api_call("blob", source.client.get_blob, entry.sha)
    if not isinstance(blob, BlobMetadata):
        raise SourceContractFailure("blob response metadata is malformed")
    if not _valid_object_id(blob.blob_sha):
        raise SourceContractFailure("blob response contains a malformed object SHA")
    if blob.blob_sha != entry.sha:
        raise SourceIdentityMismatch("blob response SHA does not match pinned tree entry")
    if type(blob.size) is not int or blob.size < 0 or not isinstance(blob.content, bytes):
        raise SourceContractFailure("blob response size or content is malformed")
    if entry.size is not None and blob.size != entry.size:
        raise SourceIdentityMismatch("blob size does not match pinned tree entry")
    if len(blob.content) != blob.size:
        raise SourceIdentityMismatch("blob content length does not match blob metadata")
    hash_name = "sha1" if len(entry.sha) == 40 else "sha256"
    git_blob = hashlib.new(hash_name)
    git_blob.update(b"blob " + str(len(blob.content)).encode("ascii") + b"\0")
    git_blob.update(blob.content)
    if git_blob.hexdigest() != entry.sha:
        raise SourceIdentityMismatch("blob bytes do not match the pinned Git blob SHA")
    return blob.content
