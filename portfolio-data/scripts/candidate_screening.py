"""In-memory, isolated candidate screening; not connected to discovery or storage."""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ipaddress
import json
import math
import re
import tomllib
from pathlib import Path
from typing import Any, Mapping, Optional, Protocol, Tuple

from candidate_identity import CandidateIdentityError, parse_candidate_json
from validate_portfolio_update import MAX_JSON_BYTES


PRIVACY_DETECTOR_ID = "portfolio-field-privacy"
PRIVACY_DETECTOR_VERSION = "1.0.0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_RULE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_LOCATION = re.compile(r"^(?:raw-candidate|candidate|line:[1-9][0-9]*|\$\.(?:title|summary|highlights|technologies|evidence)(?:\[[0-9]+\])?)$")
_EMAIL = re.compile(r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9.-])")
_KE_PHONE = re.compile(r"(?<!\d)(?:\+?254|0)(?:1|7)\d{8}(?!\d)")
_ID = re.compile(r"(?i)\b(?:national\s+id|identity\s+(?:number|no\.? )|id\s+(?:number|no\.?))\s*[:#-]?\s*\d{7,8}\b")
_TAX = re.compile(r"(?i)\b(?:kra\s+pin|tax\s+(?:id|identifier|number))\s*[:#-]?\s*[a-z]\d{9}[a-z]\b")
_SSN = re.compile(r"(?i)\bssn\s*[:#-]?\s*\d{3}-\d{2}-\d{4}\b")
_CUSTOMER_RECORD = re.compile(r"(?i)\b(?:customer|user)\s+(?:record|profile|email|phone|address|name)\s*[:#-]")
_CONFIDENTIAL_RECORD = re.compile(r"(?i)\b(?:confidential|non-public|internal-only)\s+(?:customer\s+)?(?:invoice|payroll|account|financial|business)\s+(?:record|statement|forecast|ledger)\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PRIVATE_HOST = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:internal|intranet|corp|local)\b")
_CUSTOMER_CONTEXT = re.compile(r"(?i)\b(?:customer|user|client)\b.{0,100}\b(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?:\+?\d[\d ()-]{7,}\d)|(?:account|invoice|order|payment|balance|address|phone|email|name)\s*[:#=])")
_CUSTOMER_BUSINESS = re.compile(r"(?i)\b(?:customer|client|user)\s+(?:account|invoice|order|payment|balance|contract|pricing|purchase)\b|\b(?:account|invoice|order|payment|balance|contract|pricing|purchase)\s+(?:for|of)\s+(?:customer|client|user)\b")
_CONFIDENTIAL_CONTEXT = re.compile(r"(?i)\b(?:confidential|non-public|internal-only|proprietary)\b.{0,80}\b(?:revenue|profit|margin|pricing|payroll|forecast|ledger|financial|business|contract|customer|vendor)\b|\b(?:revenue|profit|margin|pricing|payroll|forecast|ledger|financial|business)\s+(?:data|details|figures|results|plan|records)\b")
_INTERNAL_CONFIG = re.compile(r"(?i)\b(?:internal|private|staging|production|prod|dev)\b.{0,80}\b(?:hostname|host|endpoint|url|config(?:uration)?|secret|token|credential|database|bucket|cluster|namespace)\b\s*[:=]")
# These are evidence-based text heuristics, not semantic classification. When
# a structured transaction, sensitive figure, or infrastructure marker matches,
# screening blocks it; unlabeled details without these markers can still evade
# detection, and overly terse matches may require human review.
_CUSTOMER_TRANSACTION = re.compile(r"(?i)\b(?:invoice|order|payment|transaction|account)\s*(?:#|no\.?|id|ref(?:erence)?)?\s*[:#=-]?\s*[A-Z0-9-]{4,}\b.{0,60}\b(?:KES|USD|EUR|GBP|amount|balance|paid|due)\b")
_FINANCIAL_FIGURES = re.compile(r"(?i)\b(?:revenue|profit|margin|payroll|forecast|ledger|financial|business)\s+(?:data|details|figures|results|plan|records)\s*[:=-]?\s*(?:KES|USD|EUR|GBP|\$|£|€)?\s*\d[\d,.% ]*")
_INFRA_CONFIG = re.compile(r"(?i)\b(?:DATABASE_URL|REDIS_URL|MONGO_URI|POSTGRES(?:_URL)?|MYSQL(?:_URL)?|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|API_SECRET|SERVICE_TOKEN|INTERNAL_API_URL)\s*[:=]")
_INFRA_HOST = re.compile(r"(?i)\b(?:db|database|redis|mongo|postgres|mysql|kafka|rabbitmq|auth|admin|api)[-.][a-z0-9-]*(?:prod|production|stage|staging|cluster|private|corp)[a-z0-9.-]*\b")

_PRIVACY_RULE_PATTERNS = (
    ("personal_email", _EMAIL), ("personal_phone", _KE_PHONE),
    ("identity_identifier", _ID), ("tax_identifier", _TAX),
    ("identity_identifier", _SSN), ("customer_record", _CUSTOMER_RECORD),
    ("customer_identifiable_information", _CUSTOMER_CONTEXT),
    ("customer_business_record", _CUSTOMER_BUSINESS),
    ("confidential_business_record", _CONFIDENTIAL_RECORD),
    ("confidential_business_detail", _CONFIDENTIAL_CONTEXT),
    ("internal_configuration", _INTERNAL_CONFIG),
    ("nonpublic_infrastructure", _PRIVATE_HOST),
    ("customer_business_record", _CUSTOMER_TRANSACTION),
    ("confidential_business_detail", _FINANCIAL_FIGURES),
    ("internal_configuration", _INFRA_CONFIG),
    ("nonpublic_infrastructure", _INFRA_HOST),
    ("nonpublic_infrastructure", _IPV4),
)


_PRIVACY_SCANNED_FIELDS = ("title", "summary", "highlights", "technologies", "evidence")
_PRIVATE_IPV4_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def _privacy_configuration_digest(
    rules=_PRIVACY_RULE_PATTERNS,
    fields=_PRIVACY_SCANNED_FIELDS,
    private_ipv4_networks=_PRIVATE_IPV4_NETWORKS,
) -> str:
    serialized = json.dumps(
        {"detector_id": PRIVACY_DETECTOR_ID,
         "detector_version": PRIVACY_DETECTOR_VERSION,
         "scanned_fields": list(fields),
         "rules": [{"rule_id": rule_id, "pattern": pattern.pattern,
                    "flags": pattern.flags} for rule_id, pattern in rules],
         "private_ipv4_networks": list(private_ipv4_networks)},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(serialized).hexdigest()


PRIVACY_CONFIG_ID = _privacy_configuration_digest()


class ScreeningStatus(str, Enum):
    CLEAN = "clean"
    FINDING = "finding"
    SCANNER_ERROR = "scanner_error"



@dataclass(frozen=True)
class GitleaksScanMetadata:
    scanner_identity: str
    configuration_identity: str
    version: str

    def __post_init__(self):
        if not all(isinstance(value, str) and value for value in (
            self.scanner_identity, self.configuration_identity, self.version,
        )):
            raise ValueError("Gitleaks scan metadata is invalid")
        if not _VERSION.fullmatch(self.version):
            raise ValueError("Gitleaks scan metadata is invalid")
        match = re.fullmatch(r"gitleaks/(.+)@sha256:([0-9a-f]{64})", self.scanner_identity)
        if not match or match.group(1) != self.version:
            raise ValueError("Gitleaks scan metadata is invalid")
        if not _HEX.fullmatch(self.configuration_identity):
            raise ValueError("Gitleaks scan metadata is invalid")



class ScreeningOperationalError(Exception):
    """Sanitized scanner or configuration error, optionally carrying verified scan metadata."""

    def __init__(self, code: str, *, scanner_metadata=None):
        safe_code = code if isinstance(code, str) and _RULE.fullmatch(code) else "scanner_failure"
        self.code = safe_code
        self.scanner_metadata = scanner_metadata
        super().__init__(safe_code)



@dataclass(frozen=True)
class ScreeningFinding:
    detector_id: str
    detector_version: str
    rule_id: str
    location: str
    severity: str
    raw_candidate_sha256: str
    scanner_identity: str
    configuration_identity: str

    def __post_init__(self):
        if not all(isinstance(value, str) and value for value in (
            self.detector_id, self.detector_version, self.rule_id, self.location,
            self.severity, self.scanner_identity, self.configuration_identity,
        )):
            raise ValueError("screening finding metadata is invalid")
        if (not _RULE.fullmatch(self.detector_id) or not _VERSION.fullmatch(self.detector_version)
                or not _RULE.fullmatch(self.rule_id) or not _LOCATION.fullmatch(self.location)
                or self.severity not in ("secret", "sensitive_data")):
            raise ValueError("screening finding metadata is invalid")
        if self.detector_id == "gitleaks":
            if not re.fullmatch(r"gitleaks/[^@]+@sha256:[0-9a-f]{64}", self.scanner_identity):
                raise ValueError("screening scanner identity is invalid")
        elif (self.detector_id != PRIVACY_DETECTOR_ID
              or self.scanner_identity != "portfolio-field-privacy@1.0.0"
              or self.detector_version != PRIVACY_DETECTOR_VERSION
              or self.configuration_identity != PRIVACY_CONFIG_ID):
            raise ValueError("screening scanner identity is invalid")
        if not _HEX.fullmatch(self.configuration_identity):
            raise ValueError("screening configuration identity is invalid")
        if not _HEX.fullmatch(self.raw_candidate_sha256):
            raise ValueError("screening finding digest is invalid")



@dataclass(frozen=True)
class GitleaksScanResult:
    findings: Tuple[ScreeningFinding, ...]
    metadata: Optional[GitleaksScanMetadata]

    def __post_init__(self):
        if not isinstance(self.findings, tuple) or any(
            type(finding) is not ScreeningFinding for finding in self.findings
        ):
            raise ValueError("Gitleaks scan findings are invalid")
        if self.metadata is not None and type(self.metadata) is not GitleaksScanMetadata:
            raise ValueError("Gitleaks scan metadata is invalid")


@dataclass(frozen=True)
class ScreeningResult:
    status: ScreeningStatus
    raw_candidate_sha256: str
    findings: Tuple[ScreeningFinding, ...] = field(repr=False)
    error_code: Optional[str] = None
    gitleaks_identity: Optional[str] = None
    gitleaks_configuration_identity: Optional[str] = None
    privacy_detector_id: Optional[str] = None
    privacy_detector_version: Optional[str] = None
    privacy_configuration_identity: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.status, ScreeningStatus) or not isinstance(self.raw_candidate_sha256, str) or not _HEX.fullmatch(self.raw_candidate_sha256):
            raise ValueError("screening result is invalid")
        if not isinstance(self.findings, tuple) or any(type(f) is not ScreeningFinding for f in self.findings):
            raise ValueError("screening findings are invalid")
        if self.error_code is not None and (not isinstance(self.error_code, str) or not _RULE.fullmatch(self.error_code)):
            raise ValueError("screening error code is invalid")

        privacy_values = (
            self.privacy_detector_id,
            self.privacy_detector_version,
            self.privacy_configuration_identity,
        )
        privacy_absent = all(value is None for value in privacy_values)
        privacy_present = all(isinstance(value, str) and value for value in privacy_values)
        if not privacy_absent and not privacy_present:
            raise ValueError("privacy screening metadata is incomplete")
        if privacy_present and privacy_values != (
            PRIVACY_DETECTOR_ID, PRIVACY_DETECTOR_VERSION, PRIVACY_CONFIG_ID,
        ):
            raise ValueError("privacy screening metadata is invalid")

        if (self.gitleaks_identity is None) != (self.gitleaks_configuration_identity is None):
            raise ValueError("Gitleaks screening metadata is incomplete")
        if self.gitleaks_identity is not None:
            if (not isinstance(self.gitleaks_identity, str)
                    or not re.fullmatch(r"gitleaks/[^@]+@sha256:[0-9a-f]{64}", self.gitleaks_identity)
                    or not isinstance(self.gitleaks_configuration_identity, str)
                    or not _HEX.fullmatch(self.gitleaks_configuration_identity)):
                raise ValueError("Gitleaks screening metadata is invalid")

        for finding in self.findings:
            if finding.raw_candidate_sha256 != self.raw_candidate_sha256:
                raise ValueError("screening finding candidate digest does not match result")
            if finding.detector_id == PRIVACY_DETECTOR_ID:
                if (not privacy_present
                        or finding.detector_version != self.privacy_detector_version
                        or finding.configuration_identity != self.privacy_configuration_identity):
                    raise ValueError("privacy finding metadata does not match result")
            elif finding.detector_id == "gitleaks":
                if (self.gitleaks_identity is None
                        or finding.scanner_identity != self.gitleaks_identity
                        or finding.configuration_identity != self.gitleaks_configuration_identity):
                    raise ValueError("Gitleaks finding metadata does not match result")
            else:
                raise ValueError("screening finding detector is invalid")

        if self.status is ScreeningStatus.CLEAN:
            if (self.findings or self.error_code or not privacy_present
                    or self.gitleaks_identity is None):
                raise ValueError("clean result requires completed screening metadata")
        if self.status is ScreeningStatus.FINDING:
            if (not self.findings or self.error_code or not privacy_present
                    or self.gitleaks_identity is None):
                raise ValueError("finding result requires completed screening metadata")
        if self.status is ScreeningStatus.SCANNER_ERROR and not self.error_code:
            raise ValueError("scanner error requires a stable error code")



@dataclass(frozen=True)
class GitleaksPin:
    """Centrally supplied binary/config pins; this repository defines no values."""
    executable: str
    version: str
    binary_sha256: str
    configuration_path: str
    configuration_sha256: str
    ignore_path: str
    ignore_sha256: str

    def __post_init__(self):
        if not all(isinstance(v, str) and v.strip() == v and v for v in (
            self.executable, self.version, self.configuration_path, self.ignore_path,
        )) or any("\x00" in v for v in (self.executable, self.configuration_path, self.ignore_path)):
            raise ValueError("scanner pin is invalid")
        if (not _HEX.fullmatch(self.binary_sha256)
                or not _HEX.fullmatch(self.configuration_sha256)
                or not _HEX.fullmatch(self.ignore_sha256)):
            raise ValueError("scanner digest pin is invalid")
        if not _VERSION.fullmatch(self.version):
            raise ValueError("scanner version pin is invalid")


@dataclass(frozen=True)
class ProcessResult:
    """Bounded runner response; raw output stays in memory and is never exposed."""
    returncode: int
    stdout: bytes = field(repr=False)
    timed_out: bool = False
    crashed: bool = False
    output_overflow: bool = False


class ProcessRunner(Protocol):
    def run(self, argv: Tuple[str, ...], *, stdin: bytes,
            timeout_seconds: float, max_output_bytes: int,
            expected_binary_sha256: str,
            expected_configuration_sha256: str,
            expected_ignore_sha256: str,
            expected_executable: str, expected_configuration_path: str,
            expected_ignore_path: str) -> ProcessResult:
        """Run without logging stdin/stdout/stderr; enforce byte cap and exact asset pins.

        The implementation must verify and invoke these exact paths, checking
        their digests immediately before each process launch. The version and
        scan calls must use the same pinned executable/configuration assets.
        It must use a controlled working directory and
        environment, and return truncated output only with output_overflow=True.

        This protocol is a requirement, not proof that a runner enforces it.
        Until a real runner is implemented and tested, runtime path-to-binary
        integrity and same-asset execution remain unverified.
        """


class GitleaksAdapter:
    """Boundary with caller pins, preflight hashes, and a bounded injected runner.

    The adapter hashes the bytes returned by its readers before invoking the
    runner. That preflight does not prove the launched executable is those
    bytes; runtime integrity depends on the runner contract and remains
    unverified until a real runner implements and passes runtime tests.
    """
    def __init__(self, pin: GitleaksPin, runner: ProcessRunner, *,
                 binary_reader=None, configuration_reader=None,
                 ignore_reader=None, timeout_seconds: Optional[float] = None,
                 max_output_bytes: Optional[int] = None):
        self.pin = pin
        self.runner = runner
        self.binary_reader = binary_reader or (lambda path: Path(path).read_bytes())
        self.configuration_reader = configuration_reader or (lambda path: Path(path).read_bytes())
        self.ignore_reader = ignore_reader or (lambda path: Path(path).read_bytes())
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    @property
    def scanner_identity(self) -> str:
        return "gitleaks/{}@sha256:{}".format(self.pin.version, self.pin.binary_sha256)

    @property
    def configuration_identity(self) -> str:
        return self.pin.configuration_sha256

    def _run(self, argv: Tuple[str, ...], stdin: bytes) -> ProcessResult:
        try:
            result = self.runner.run(
                argv, stdin=stdin, timeout_seconds=self.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                expected_binary_sha256=self.pin.binary_sha256,
                expected_configuration_sha256=self.pin.configuration_sha256,
                expected_ignore_sha256=self.pin.ignore_sha256,
                expected_executable=self.pin.executable,
                expected_configuration_path=self.pin.configuration_path,
                expected_ignore_path=self.pin.ignore_path,
            )
        except Exception:
            raise ScreeningOperationalError("scanner_runner_failure") from None
        if not isinstance(result, ProcessResult):
            raise ScreeningOperationalError("scanner_runner_response_invalid")
        if result.timed_out:
            raise ScreeningOperationalError("scanner_timeout")
        if result.crashed:
            raise ScreeningOperationalError("scanner_crash")
        if result.output_overflow:
            raise ScreeningOperationalError("scanner_output_overflow")
        if not isinstance(result.stdout, bytes) or type(result.returncode) is not int:
            raise ScreeningOperationalError("scanner_runner_response_invalid")
        if self.max_output_bytes is not None and len(result.stdout) > self.max_output_bytes:
            raise ScreeningOperationalError("scanner_output_overflow")
        return result


    def scan(self, raw_candidate: bytes) -> GitleaksScanResult:
        if not isinstance(raw_candidate, bytes):
            raise ScreeningOperationalError("candidate_input_invalid")
        if len(raw_candidate) > MAX_JSON_BYTES:
            raise ScreeningOperationalError("candidate_input_too_large")
        try:
            binary = self.binary_reader(self.pin.executable)
            config = self.configuration_reader(self.pin.configuration_path)
        except Exception:
            raise ScreeningOperationalError("scanner_pin_unavailable") from None
        if not isinstance(binary, bytes) or hashlib.sha256(binary).hexdigest() != self.pin.binary_sha256:
            raise ScreeningOperationalError("scanner_checksum_mismatch")
        if not isinstance(config, bytes) or hashlib.sha256(config).hexdigest() != self.pin.configuration_sha256:
            raise ScreeningOperationalError("scanner_configuration_mismatch")
        if (self.timeout_seconds is None or isinstance(self.timeout_seconds, bool)
                or not isinstance(self.timeout_seconds, (int, float))
                or not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0):
            raise ScreeningOperationalError("scanner_timeout_policy_missing")
        if (self.max_output_bytes is None or isinstance(self.max_output_bytes, bool)
                or type(self.max_output_bytes) is not int or self.max_output_bytes <= 0):
            raise ScreeningOperationalError("scanner_output_limit_missing")
        try:
            ignore = self.ignore_reader(self.pin.ignore_path)
        except Exception:
            raise ScreeningOperationalError("scanner_ignore_policy_unavailable") from None
        if (not isinstance(ignore, bytes) or hashlib.sha256(ignore).hexdigest() != self.pin.ignore_sha256
                or ignore != b""):
            raise ScreeningOperationalError("scanner_ignore_policy_mismatch")
        try:
            config_text = config.decode("utf-8")
        except UnicodeDecodeError:
            raise ScreeningOperationalError("scanner_configuration_malformed") from None
        if _has_allowlist(config_text):
            raise ScreeningOperationalError("scanner_suppressions_forbidden")

        version = self._run((self.pin.executable, "version"), b"")
        if version.returncode != 0:
            raise ScreeningOperationalError("scanner_version_check_failed")
        if not version.stdout:
            raise ScreeningOperationalError("scanner_version_response_missing")
        try:
            version_text = version.stdout.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ScreeningOperationalError("scanner_version_response_malformed") from None
        match = re.fullmatch(r"(?:gitleaks version )?(v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)", version_text)
        if not match:
            raise ScreeningOperationalError("scanner_version_response_malformed")
        if match.group(1) != self.pin.version:
            raise ScreeningOperationalError("scanner_version_mismatch")

        # This immutable metadata belongs only to this invocation.
        metadata = GitleaksScanMetadata(
            self.scanner_identity, self.configuration_identity, self.pin.version,
        )
        try:
            argv = (
                self.pin.executable, "--no-banner", "--no-color", "--redact=100",
                "--log-level=fatal",
                "--config", self.pin.configuration_path,
                "--ignore-gitleaks-allow", "--gitleaks-ignore-path", self.pin.ignore_path,
                "--report-format=json", "--report-path=-", "stdin",
            )
            result = self._run(argv, raw_candidate)
            try:
                report = json.loads(result.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ScreeningOperationalError("scanner_output_malformed") from None
            if not isinstance(report, list):
                raise ScreeningOperationalError("scanner_output_malformed")
            if result.returncode not in (0, 1):
                raise ScreeningOperationalError("scanner_exit_unexpected")

            raw_sha = hashlib.sha256(raw_candidate).hexdigest()
            findings = []
            for item in report:
                if (not isinstance(item, dict) or not isinstance(item.get("RuleID"), str)
                        or not _RULE.fullmatch(item["RuleID"])):
                    raise ScreeningOperationalError("scanner_output_malformed")
                line = item.get("StartLine")
                location = "candidate" if type(line) is not int or line < 1 else "line:{}".format(line)
                findings.append(ScreeningFinding(
                    "gitleaks", self.pin.version, item["RuleID"], location, "secret",
                    raw_sha, metadata.scanner_identity, metadata.configuration_identity,
                ))
            if result.returncode == 1 and not findings:
                raise ScreeningOperationalError("scanner_exit_inconsistent")
            return GitleaksScanResult(tuple(findings), metadata)
        except ScreeningOperationalError as error:
            raise ScreeningOperationalError(
                error.code, scanner_metadata=metadata,
            ) from None
        except Exception:
            raise ScreeningOperationalError(
                "scanner_adapter_failure", scanner_metadata=metadata,
            ) from None



def _has_allowlist(config_text: str) -> bool:
    """Parse TOML and fail closed on malformed or unsafe structures."""
    if not isinstance(config_text, str):
        raise ScreeningOperationalError("scanner_configuration_malformed")
    try:
        parsed = tomllib.loads(config_text)
    except tomllib.TOMLDecodeError:
        raise ScreeningOperationalError("scanner_configuration_malformed") from None
    if not isinstance(parsed, dict):
        raise ScreeningOperationalError("scanner_configuration_malformed")

    # Inherited configurations can introduce allowlists that are not visible
    # in this document. Reject inheritance rather than resolving external or
    # embedded Gitleaks configurations.
    extend = parsed.get("extend")
    if extend is not None:
        if not isinstance(extend, dict):
            raise ScreeningOperationalError("scanner_configuration_malformed")
        if set(extend) - {"useDefault", "path"}:
            raise ScreeningOperationalError("scanner_configuration_malformed")

        use_default = extend.get("useDefault", False)
        if type(use_default) is not bool:
            raise ScreeningOperationalError("scanner_configuration_malformed")
        if use_default:
            return True

        inherited_path = extend.get("path", "")
        if not isinstance(inherited_path, str):
            raise ScreeningOperationalError("scanner_configuration_malformed")
        if inherited_path.strip():
            return True

    def inspect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ScreeningOperationalError("scanner_configuration_malformed")
                if key.lower() in ("allowlist", "allowlists"):
                    return True
                if inspect(child):
                    return True
            return False
        if isinstance(value, list):
            return any(inspect(child) for child in value)
        if value is None or isinstance(value, (str, int, float, bool)):
            return False
        if isinstance(value, (tomllib.TOMLDecodeError,)):
            raise ScreeningOperationalError("scanner_configuration_malformed")
        if value.__class__.__module__ == "datetime":
            return False
        # Unknown TOML structures fail closed.
        raise ScreeningOperationalError("scanner_configuration_malformed")

    return inspect(parsed)


def _privacy_findings(candidate: Any, raw_sha: str) -> Tuple[ScreeningFinding, ...]:
    if not isinstance(candidate, Mapping):
        raise ScreeningOperationalError("candidate_structure_unreadable")
    fields = _PRIVACY_SCANNED_FIELDS
    found = set()
    for field_name in fields:
        value = candidate.get(field_name)
        values = enumerate(value) if isinstance(value, list) else ((None, value),)
        for index, text in values:
            if not isinstance(text, str):
                continue
            location = "$.{}{}".format(field_name, "[{}]".format(index) if index is not None else "")
            for rule_id, pattern in _PRIVACY_RULE_PATTERNS:
                if pattern is not _IPV4 and pattern.search(text):
                    found.add((rule_id, location))
            for address in _IPV4.findall(text):
                try:
                    ip = ipaddress.IPv4Address(address)
                except ipaddress.AddressValueError:
                    continue
                if ip.is_private and any(ip in ipaddress.ip_network(network) for network in _PRIVATE_IPV4_NETWORKS):
                    found.add(("nonpublic_infrastructure", location))
    identity = "{}@{}".format(PRIVACY_DETECTOR_ID, PRIVACY_DETECTOR_VERSION)
    return tuple(ScreeningFinding(
        PRIVACY_DETECTOR_ID, PRIVACY_DETECTOR_VERSION, rule_id, location,
        "sensitive_data", raw_sha, identity, PRIVACY_CONFIG_ID,
    ) for rule_id, location in sorted(found))


def _metadata_matches_adapter(metadata, gitleaks) -> bool:
    if type(metadata) is not GitleaksScanMetadata:
        return False
    try:
        identity = metadata.scanner_identity
        configuration = metadata.configuration_identity
        version = metadata.version
        pin = getattr(gitleaks, "pin", None)
        pin_version = pin.version
        binary_sha256 = pin.binary_sha256
        configuration_sha256 = pin.configuration_sha256
    except Exception:
        return False
    if type(pin) is not GitleaksPin:
        return False
    if (not isinstance(identity, str)
            or not isinstance(configuration, str)
            or not isinstance(version, str)):
        return False
    expected_identity = "gitleaks/{}@sha256:{}".format(pin_version, binary_sha256)
    return (
        identity == expected_identity
        and configuration == configuration_sha256
        and version == pin_version
    )


def _valid_scanner_finding(finding):
    if type(finding) is not ScreeningFinding:
        return False
    try:
        ScreeningFinding(
            finding.detector_id, finding.detector_version, finding.rule_id,
            finding.location, finding.severity, finding.raw_candidate_sha256,
            finding.scanner_identity, finding.configuration_identity,
        )
    except Exception:
        return False
    return True


def _result_with_metadata(status, raw_sha, findings, *, privacy_completed,
                          scanner_metadata=None, error_code=None):
    if scanner_metadata is not None and type(scanner_metadata) is not GitleaksScanMetadata:
        scanner_metadata = None
    return ScreeningResult(
        status=status,
        raw_candidate_sha256=raw_sha,
        findings=findings,
        error_code=error_code,
        gitleaks_identity=(scanner_metadata.scanner_identity if scanner_metadata else None),
        gitleaks_configuration_identity=(scanner_metadata.configuration_identity if scanner_metadata else None),
        privacy_detector_id=(PRIVACY_DETECTOR_ID if privacy_completed else None),
        privacy_detector_version=(PRIVACY_DETECTOR_VERSION if privacy_completed else None),
        privacy_configuration_identity=(PRIVACY_CONFIG_ID if privacy_completed else None),
    )


def _scanner_error_result(raw_sha, privacy, error_code, *,
                          privacy_completed, scanner_metadata=None):
    return _result_with_metadata(
        ScreeningStatus.SCANNER_ERROR, raw_sha, privacy,
        privacy_completed=privacy_completed,
        scanner_metadata=scanner_metadata,
        error_code=error_code,
    )


def screen_candidate(raw_candidate: bytes, gitleaks: GitleaksAdapter) -> ScreeningResult:
    """Run deterministic privacy checks and Gitleaks without persistence."""
    if not isinstance(raw_candidate, bytes):
        raise ScreeningOperationalError("candidate_input_invalid")
    raw_sha = hashlib.sha256(raw_candidate).hexdigest()
    if len(raw_candidate) > MAX_JSON_BYTES:
        return _result_with_metadata(
            ScreeningStatus.SCANNER_ERROR, raw_sha, (),
            privacy_completed=False, error_code="candidate_input_too_large",
        )

    try:
        candidate = parse_candidate_json(raw_candidate)
        privacy = list(_privacy_findings(candidate, raw_sha))
        # Also inspect the original serialized bytes for sensitive text in fields
        # outside the current schema or in JSON encodings not surfaced as strings.
        raw_text = raw_candidate.decode("utf-8")
        present_rules = {finding.rule_id for finding in privacy}
        identity = "{}@{}".format(PRIVACY_DETECTOR_ID, PRIVACY_DETECTOR_VERSION)
        for rule_id, pattern in _PRIVACY_RULE_PATTERNS:
            if pattern is not _IPV4 and rule_id not in present_rules and pattern.search(raw_text):
                privacy.append(ScreeningFinding(
                    PRIVACY_DETECTOR_ID, PRIVACY_DETECTOR_VERSION, rule_id,
                    "raw-candidate", "sensitive_data", raw_sha, identity,
                    PRIVACY_CONFIG_ID,
                ))
        for address in _IPV4.findall(raw_text):
            try:
                ip = ipaddress.IPv4Address(address)
            except ipaddress.AddressValueError:
                continue
            if (any(ip in ipaddress.ip_network(network) for network in _PRIVATE_IPV4_NETWORKS)
                    and "nonpublic_infrastructure" not in present_rules):
                privacy.append(ScreeningFinding(
                    PRIVACY_DETECTOR_ID, PRIVACY_DETECTOR_VERSION,
                    "nonpublic_infrastructure", "raw-candidate", "sensitive_data",
                    raw_sha, identity, PRIVACY_CONFIG_ID,
                ))
        privacy = tuple(privacy)
    except Exception:
        return _result_with_metadata(
            ScreeningStatus.SCANNER_ERROR, raw_sha, (),
            privacy_completed=False, error_code="candidate_structure_unreadable",
        )

    try:
        scan_result = gitleaks.scan(raw_candidate)
    except ScreeningOperationalError as error:
        metadata = error.scanner_metadata
        if not _metadata_matches_adapter(metadata, gitleaks):
            metadata = None
        return _scanner_error_result(
            raw_sha, privacy, error.code, privacy_completed=True,
            scanner_metadata=metadata,
        )
    except Exception:
        return _scanner_error_result(
            raw_sha, privacy, "scanner_adapter_failure",
            privacy_completed=True,
        )

    if type(scan_result) is not GitleaksScanResult:
        return _scanner_error_result(
            raw_sha, privacy, "scanner_response_invalid",
            privacy_completed=True,
        )

    try:
        metadata = scan_result.metadata
        secret_findings = scan_result.findings
    except Exception:
        return _scanner_error_result(
            raw_sha, privacy, "scanner_response_invalid",
            privacy_completed=True,
        )
    if not isinstance(secret_findings, tuple):
        return _scanner_error_result(
            raw_sha, privacy, "scanner_response_invalid",
            privacy_completed=True,
        )
    if metadata is None:
        return _scanner_error_result(
            raw_sha, privacy, "scanner_identity_unverified",
            privacy_completed=True,
        )
    if not _metadata_matches_adapter(metadata, gitleaks):
        return _scanner_error_result(
            raw_sha, privacy, "scanner_identity_mismatch",
            privacy_completed=True,
        )

    for finding in secret_findings:
        if (not _valid_scanner_finding(finding)
                or finding.detector_id != "gitleaks"
                or finding.raw_candidate_sha256 != raw_sha
                or finding.scanner_identity != metadata.scanner_identity
                or finding.configuration_identity != metadata.configuration_identity
                or finding.detector_version != metadata.version):
            return _scanner_error_result(
                raw_sha, privacy, "scanner_response_invalid",
                privacy_completed=True, scanner_metadata=metadata,
            )

    findings = tuple(sorted(
        privacy + secret_findings,
        key=lambda finding: (finding.detector_id, finding.rule_id, finding.location),
    ))
    status = ScreeningStatus.FINDING if findings else ScreeningStatus.CLEAN
    return _result_with_metadata(
        status, raw_sha, findings, privacy_completed=True,
        scanner_metadata=metadata,
    )
