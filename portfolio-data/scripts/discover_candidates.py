"""Discover and validate candidate files from a trusted pinned source.

This module is intentionally in-memory only. It has no HTTP implementation,
credentials, persistence, logging, or GitHub workflow integration.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import math
import re
from typing import Any, Mapping, Optional, Tuple

from candidate_screening import (
    GitleaksAdapter,
    GitleaksPin,
    ScreeningResult,
    ScreeningStatus,
    screen_candidate,
)
from candidate_identity import (
    CandidateIdentity,
    CandidateIdentityError,
    canonicalize_json,
    identify_candidate,
    parse_candidate_json,
)
from trusted_source import (
    PinnedSource,
    PinnedRepository,
    ResolvedSource,
    SourceAuthorizationFailure,
    SourceIdentityMismatch,
    SourceIncompleteTree,
    SourceRateLimited,
    SourceResourceNotFound,
    SourceResolverError,
    SourceTransientFailure,
    TreeEntry,
    enumerate_tree,
    read_pinned_blob,
    registered_repository_from_entry,
    resolve_registered_source,
    verify_pinned_commit,
)
from validate_portfolio_update import (
    MAX_JSON_BYTES,
    ValidationConfigurationFailure,
    ValidationFailure,
    validate_candidate_data,
    validate_pipeline_registry,
)


_CANDIDATE_PATH = re.compile(
    r"\.portfolio/updates/([a-z0-9][a-z0-9-]{0,63})/candidate-([0-9]{3})\.json",
    re.ASCII,
)
_REGULAR_BLOB_MODES = frozenset({"100644", "100755"})


class DiscoveryFailureCode(str, Enum):
    INVALID_REGISTRY = "invalid_registry"
    REPOSITORY_ID_REQUIRED = "repository_id_required"
    PROJECT_DISABLED = "project_disabled"
    SOURCE_IDENTITY_OR_AUTHORIZATION = "source_identity_or_authorization"
    SOURCE_NOT_FOUND = "source_not_found"
    TRANSIENT_SOURCE_FAILURE = "transient_source_failure"
    INCOMPLETE_TREE = "incomplete_tree"
    SOURCE_CONTRACT_FAILURE = "source_contract_failure"
    INTEGRITY_CONFLICT = "integrity_conflict"
    VALIDATION_CONFIGURATION_FAILURE = "validation_configuration_failure"
    SCREENING_CONFIGURATION_FAILURE = "screening_configuration_failure"


class CandidateIssueCode(str, Enum):
    PATH_UPDATE_ID_MISMATCH = "path_update_id_mismatch"
    UNSUPPORTED_FILE_TYPE = "unsupported_file_type"
    DECLARED_SIZE_MISSING = "declared_size_missing"
    CANDIDATE_TOO_LARGE = "candidate_too_large"
    INVALID_JSON_OR_IDENTITY = "invalid_json_or_identity"
    VALIDATION_FAILED = "validation_failed"
    PROJECT_ID_MISMATCH = "project_id_mismatch"


class DiscoveryFailure(Exception):
    """Sanitized, stable failure category; never includes candidate contents."""

    def __init__(self, code: DiscoveryFailureCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True)
class CandidateIssue:
    candidate_path: str
    code: CandidateIssueCode


@dataclass(frozen=True)
class DiscoveredCandidate:
    project_id: str
    update_id: str
    candidate_path: str
    sequence: int
    source_commit_sha: str
    raw_bytes: bytes = field(repr=False)
    candidate: Mapping[str, Any] = field(repr=False)
    identity: CandidateIdentity
    observation_id: str
    revision_kind: str
    previous_submission_id: Optional[str]
    screening_result: ScreeningResult = field(repr=False)


@dataclass(frozen=True)
class CandidateScreeningRecord:
    candidate_path: str
    update_id: str
    sequence: int
    screening_result: ScreeningResult = field(repr=False)


@dataclass(frozen=True)
class DiscoveryBatch:
    project_id: str
    repository_id: int
    source_commit_sha: str
    candidates: Tuple[DiscoveredCandidate, ...]
    issues: Tuple[CandidateIssue, ...]
    screening_findings: Tuple[CandidateScreeningRecord, ...]
    screening_errors: Tuple[CandidateScreeningRecord, ...]

    @property
    def screening_complete(self) -> bool:
        """True when every candidate reaching screening received a decision."""
        return not self.screening_errors


def _validate_screening_adapter(adapter: Any) -> None:
    """Reject missing or structurally invalid screening configuration."""
    try:
        if type(adapter) is not GitleaksAdapter:
            raise ValueError("adapter type")

        pin = adapter.pin
        if type(pin) is not GitleaksPin:
            raise ValueError("pin type")

        GitleaksPin(
            pin.executable, pin.version, pin.binary_sha256,
            pin.configuration_path, pin.configuration_sha256,
            pin.ignore_path, pin.ignore_sha256,
        )

        runner = adapter.runner
        if not callable(getattr(runner, "run", None)):
            raise ValueError("runner")
        for name in ("binary_reader", "configuration_reader", "ignore_reader"):
            if not callable(getattr(adapter, name, None)):
                raise ValueError("reader")

        timeout = adapter.timeout_seconds
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("timeout policy")

        output_limit = adapter.max_output_bytes
        if type(output_limit) is not int or output_limit <= 0:
            raise ValueError("output policy")
    except Exception:
        raise DiscoveryFailure(
            DiscoveryFailureCode.SCREENING_CONFIGURATION_FAILURE
        ) from None


def _screen_discovered_candidate(
    raw_bytes: bytes,
    raw_sha256: str,
    adapter: GitleaksAdapter,
) -> ScreeningResult:
    """Run screening and independently validate its in-memory response."""
    try:
        result = screen_candidate(raw_bytes, adapter)
    except Exception:
        return ScreeningResult(
            ScreeningStatus.SCANNER_ERROR, raw_sha256, (),
            "screening_adapter_failure",
        )

    try:
        if type(result) is not ScreeningResult:
            raise ValueError("screening response type")

        checked = ScreeningResult(
            status=result.status,
            raw_candidate_sha256=result.raw_candidate_sha256,
            findings=result.findings,
            error_code=result.error_code,
            gitleaks_identity=result.gitleaks_identity,
            gitleaks_configuration_identity=result.gitleaks_configuration_identity,
            privacy_detector_id=result.privacy_detector_id,
            privacy_detector_version=result.privacy_detector_version,
            privacy_configuration_identity=result.privacy_configuration_identity,
        )
        if checked.raw_candidate_sha256 != raw_sha256:
            raise ValueError("candidate digest mismatch")
        return checked
    except Exception:
        return ScreeningResult(
            ScreeningStatus.SCANNER_ERROR, raw_sha256, (),
            "screening_response_invalid",
        )


def candidate_path_parts(path: str) -> Optional[Tuple[str, int]]:
    """Return exact update/sequence components, without normalizing the path."""
    if not isinstance(path, str):
        return None
    match = _CANDIDATE_PATH.fullmatch(path)
    if match is None:
        return None
    sequence = int(match.group(2))
    if sequence <= 0:
        return None
    return match.group(1), sequence


def _translate_source_error(error: SourceResolverError) -> DiscoveryFailure:
    if isinstance(error, SourceIncompleteTree):
        return DiscoveryFailure(DiscoveryFailureCode.INCOMPLETE_TREE)
    if isinstance(error, (SourceIdentityMismatch, SourceAuthorizationFailure)):
        return DiscoveryFailure(
            DiscoveryFailureCode.SOURCE_IDENTITY_OR_AUTHORIZATION
        )
    if isinstance(error, (SourceTransientFailure, SourceRateLimited)):
        return DiscoveryFailure(DiscoveryFailureCode.TRANSIENT_SOURCE_FAILURE)
    if isinstance(error, SourceResourceNotFound):
        return DiscoveryFailure(DiscoveryFailureCode.SOURCE_NOT_FOUND)
    return DiscoveryFailure(DiscoveryFailureCode.SOURCE_CONTRACT_FAILURE)


def prepare_registered_source(
    project_id: str,
    registry: Mapping[str, Any],
    app_client: Any,
    *,
    expected_app_id: int,
) -> PinnedSource:
    """Validate registry inputs and resolve one immutable default-branch pin.

    Retain the returned pin and pass it to ``discover_pinned_source`` on retry;
    this function is the only discovery operation that resolves the branch head.
    """
    if not isinstance(project_id, str) or not project_id:
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    try:
        validate_pipeline_registry(registry)
    except ValidationConfigurationFailure:
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    projects = registry.get("projects")
    if not isinstance(projects, Mapping) or project_id not in projects:
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    entry = projects[project_id]
    if not isinstance(entry, Mapping):
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    if entry.get("enabled") is not True:
        raise DiscoveryFailure(DiscoveryFailureCode.PROJECT_DISABLED)
    repository_id = entry.get("repository_id")
    if type(repository_id) is not int or repository_id <= 0:
        raise DiscoveryFailure(DiscoveryFailureCode.REPOSITORY_ID_REQUIRED)

    try:
        registered = registered_repository_from_entry(project_id, entry)
        return resolve_registered_source(
            registered, app_client, expected_app_id=expected_app_id
        )
    except SourceResolverError as error:
        raise _translate_source_error(error) from None


def _observation_id(
    repository_id: int, commit_sha: str, candidate_path: str, raw_sha256: str
) -> str:
    observation = {
        "candidate_path": candidate_path,
        "raw_sha256": raw_sha256,
        "source_commit_sha": commit_sha,
        "source_repository_id": repository_id,
    }
    digest = hashlib.sha256(canonicalize_json(observation)).hexdigest()
    return "sha256:" + digest


def _read_candidate_blob(
    source: ResolvedSource, tree: Any, entry: TreeEntry
) -> bytes:
    try:
        return read_pinned_blob(source, tree, entry)
    except SourceResolverError as error:
        if isinstance(error, SourceIdentityMismatch):
            raise DiscoveryFailure(DiscoveryFailureCode.INTEGRITY_CONFLICT) from None
        raise _translate_source_error(error) from None


def discover_pinned_source(
    pinned_source: PinnedSource,
    project_id: str,
    registry: Mapping[str, Any],
    schema: Any,
    *,
    screening_adapter: Optional[GitleaksAdapter] = None,
) -> DiscoveryBatch:
    """Discover all valid candidates using only an existing commit checkpoint.

    Repeating this function after a transient failure uses the same pinned
    commit, then the same verified tree and blob identities; it never resolves a
    branch. Candidate payloads and detailed validation data remain in memory.
    """
    _validate_screening_adapter(screening_adapter)
    if not isinstance(project_id, str) or not project_id:
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    try:
        validate_pipeline_registry(registry)
    except ValidationConfigurationFailure:
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    projects = registry.get("projects")
    if not isinstance(projects, Mapping) or project_id not in projects:
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    entry = projects[project_id]
    if not isinstance(entry, Mapping):
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)
    if entry.get("enabled") is not True:
        raise DiscoveryFailure(DiscoveryFailureCode.PROJECT_DISABLED)
    repository_id = entry.get("repository_id")
    full_name = entry.get("repository")
    if type(repository_id) is not int or repository_id <= 0:
        raise DiscoveryFailure(DiscoveryFailureCode.REPOSITORY_ID_REQUIRED)
    if not isinstance(full_name, str):
        raise DiscoveryFailure(DiscoveryFailureCode.INVALID_REGISTRY)

    if isinstance(pinned_source, PinnedSource) and isinstance(
        pinned_source.repository, PinnedRepository
    ) and (
        pinned_source.repository.repository_id != repository_id
        or pinned_source.repository.full_name != full_name
    ):
        raise DiscoveryFailure(
            DiscoveryFailureCode.SOURCE_IDENTITY_OR_AUTHORIZATION
        )

    try:
        source = verify_pinned_commit(pinned_source)
    except SourceResolverError as error:
        raise _translate_source_error(error) from None
    try:
        tree = enumerate_tree(source)
    except SourceResolverError as error:
        if isinstance(error, SourceIdentityMismatch):
            raise DiscoveryFailure(
                DiscoveryFailureCode.INTEGRITY_CONFLICT
            ) from None
        raise _translate_source_error(error) from None

    eligible = []
    issues = []
    for entry_in_tree in tree.entries:
        parts = candidate_path_parts(entry_in_tree.path)
        if parts is None:
            continue
        update_id, sequence = parts
        if entry_in_tree.type != "blob" or entry_in_tree.mode not in _REGULAR_BLOB_MODES:
            issues.append(
                CandidateIssue(
                    entry_in_tree.path, CandidateIssueCode.UNSUPPORTED_FILE_TYPE
                )
            )
            continue
        if entry_in_tree.size is None:
            issues.append(
                CandidateIssue(
                    entry_in_tree.path, CandidateIssueCode.DECLARED_SIZE_MISSING
                )
            )
            continue
        if entry_in_tree.size > MAX_JSON_BYTES:
            issues.append(
                CandidateIssue(
                    entry_in_tree.path, CandidateIssueCode.CANDIDATE_TOO_LARGE
                )
            )
            continue
        eligible.append((update_id, sequence, entry_in_tree))

    eligible.sort(key=lambda item: (item[0], item[1]))
    raw_hashes_by_update = {}
    discovered = []
    screening_findings = []
    screening_errors = []
    previous_by_update = {}
    for update_id, sequence, tree_entry in eligible:
        raw_bytes = _read_candidate_blob(source, tree, tree_entry)
        if len(raw_bytes) > MAX_JSON_BYTES:
            issues.append(
                CandidateIssue(tree_entry.path, CandidateIssueCode.CANDIDATE_TOO_LARGE)
            )
            continue

        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        prior_hashes = raw_hashes_by_update.setdefault(update_id, set())
        if raw_sha256 in prior_hashes:
            raise DiscoveryFailure(DiscoveryFailureCode.INTEGRITY_CONFLICT)
        prior_hashes.add(raw_sha256)

        try:
            candidate = parse_candidate_json(raw_bytes)
            identity = identify_candidate(raw_bytes)
        except CandidateIdentityError:
            issues.append(
                CandidateIssue(
                    tree_entry.path, CandidateIssueCode.INVALID_JSON_OR_IDENTITY
                )
            )
            continue

        if not isinstance(candidate, dict) or candidate.get("update_id") != update_id:
            issues.append(
                CandidateIssue(
                    tree_entry.path, CandidateIssueCode.PATH_UPDATE_ID_MISMATCH
                )
            )
            continue
        if candidate.get("project_id") != project_id:
            issues.append(
                CandidateIssue(tree_entry.path, CandidateIssueCode.PROJECT_ID_MISMATCH)
            )
            continue

        try:
            validation_errors = validate_candidate_data(candidate, schema, registry)
        except ValidationFailure:
            raise DiscoveryFailure(
                DiscoveryFailureCode.VALIDATION_CONFIGURATION_FAILURE
            ) from None
        if validation_errors:
            issues.append(
                CandidateIssue(tree_entry.path, CandidateIssueCode.VALIDATION_FAILED)
            )
            continue

        previous = previous_by_update.get(update_id)
        if previous is None:
            revision_kind = "initial"
            previous_submission_id = None
        else:
            previous_submission_id = previous.submission_id
            revision_kind = (
                "formatting_only"
                if previous.canonical_sha256 == identity.canonical_sha256
                else "canonical_revision"
            )

        # Source revision history advances for every schema-valid candidate,
        # independently of its screening outcome.
        previous_by_update[update_id] = identity

        observation_id = _observation_id(
            repository_id,
            source.repository.commit_sha,
            tree_entry.path,
            identity.raw_sha256,
        )
        screening_result = _screen_discovered_candidate(
            raw_bytes, identity.raw_sha256, screening_adapter
        )
        screening_record = CandidateScreeningRecord(
            candidate_path=tree_entry.path,
            update_id=update_id,
            sequence=sequence,
            screening_result=screening_result,
        )

        if screening_result.status is ScreeningStatus.FINDING:
            screening_findings.append(screening_record)
            continue
        if screening_result.status is ScreeningStatus.SCANNER_ERROR:
            screening_errors.append(screening_record)
            continue
        if screening_result.status is not ScreeningStatus.CLEAN:
            screening_errors.append(CandidateScreeningRecord(
                tree_entry.path,
                update_id,
                sequence,
                ScreeningResult(
                    ScreeningStatus.SCANNER_ERROR,
                    identity.raw_sha256,
                    (),
                    "screening_response_invalid",
                ),
            ))
            continue

        discovered_candidate = DiscoveredCandidate(
            project_id=project_id,
            update_id=update_id,
            candidate_path=tree_entry.path,
            sequence=sequence,
            source_commit_sha=source.repository.commit_sha,
            raw_bytes=raw_bytes,
            candidate=candidate,
            identity=identity,
            observation_id=observation_id,
            revision_kind=revision_kind,
            previous_submission_id=previous_submission_id,
            screening_result=screening_result,
        )
        discovered.append(discovered_candidate)

    return DiscoveryBatch(
        project_id=project_id,
        repository_id=repository_id,
        source_commit_sha=source.repository.commit_sha,
        candidates=tuple(discovered),
        issues=tuple(issues),
        screening_findings=tuple(screening_findings),
        screening_errors=tuple(screening_errors),
    )
