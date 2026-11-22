import contextlib
import hashlib
import io
import json
import re
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "portfolio-data" / "scripts"))

from candidate_screening import (  # noqa: E402
    GitleaksAdapter, GitleaksPin, GitleaksScanMetadata, GitleaksScanResult,
    PRIVACY_CONFIG_ID, _EMAIL, _PRIVACY_RULE_PATTERNS, _has_allowlist,
    _privacy_configuration_digest, ProcessResult, ScreeningFinding,
    ScreeningOperationalError, ScreeningResult, ScreeningStatus, screen_candidate,
)


BINARY = b"synthetic gitleaks executable fixture"
CONFIG = b'title = "synthetic central config"\n'
IGNORE = b""
PIN = GitleaksPin(
    "gitleaks-fixture", "8.25.0", hashlib.sha256(BINARY).hexdigest(),
    "central-gitleaks.toml", hashlib.sha256(CONFIG).hexdigest(),
    "central-empty-gitleaksignore", hashlib.sha256(IGNORE).hexdigest(),
)


def candidate(text="A public backend engineering update."):
    return json.dumps({
        "schema_version": "1.0", "project_id": "companyhub",
        "update_id": "synthetic-update", "date": "2026-11-20",
        "category": "engineering", "title": text, "summary": "A general implementation summary.",
        "highlights": ["Added a documented API boundary."],
        "technologies": ["Python"], "evidence": ["https://example.invalid/docs"],
        "destination": "engineering",
    }).encode("utf-8")


class FakeRunner:
    def __init__(self, scan_result=None, version="8.25.0"):
        self.scan_result = scan_result or ProcessResult(0, b"[]")
        self.version = version
        self.calls = []

    def run(self, argv, *, stdin, timeout_seconds, max_output_bytes,
            expected_binary_sha256, expected_configuration_sha256,
            expected_ignore_sha256, expected_executable,
            expected_configuration_path, expected_ignore_path):
        self.calls.append((argv, stdin, timeout_seconds))
        if len(self.calls) == 1:
            return ProcessResult(0, ("gitleaks version " + self.version).encode())
        return self.scan_result


def make_adapter(runner=None, **kwargs):
    options = {"timeout_seconds": 3.0, "max_output_bytes": 8192,
               "binary_reader": lambda path: BINARY,
               "configuration_reader": lambda path: CONFIG,
               "ignore_reader": lambda path: IGNORE}
    options.update(kwargs)
    return GitleaksAdapter(PIN, runner or FakeRunner(), **options)


class CandidateScreeningTests(unittest.TestCase):
    def test_clean_result_and_raw_sha_binding(self):
        raw = candidate()
        result = screen_candidate(raw, make_adapter())
        self.assertEqual(result.status, ScreeningStatus.CLEAN)
        self.assertEqual(result.raw_candidate_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(result.findings, ())
        self.assertEqual(result.gitleaks_identity,
                         "gitleaks/8.25.0@sha256:" + hashlib.sha256(BINARY).hexdigest())
        self.assertEqual(result.gitleaks_configuration_identity, hashlib.sha256(CONFIG).hexdigest())
        self.assertEqual(result.privacy_configuration_identity, PRIVACY_CONFIG_ID)

    def test_gitleaks_finding_is_sanitized(self):
        raw = candidate()
        report = json.dumps([{
            "RuleID": "synthetic-test-rule", "StartLine": 4,
            "Secret": "SYNTHETIC_SECRET_VALUE", "Match": "SYNTHETIC_SECRET_VALUE",
        }]).encode()
        runner = FakeRunner(ProcessResult(1, report))
        result = screen_candidate(raw, make_adapter(runner))
        self.assertEqual(result.status, ScreeningStatus.FINDING)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "synthetic-test-rule")
        self.assertEqual(finding.raw_candidate_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(result.gitleaks_configuration_identity, hashlib.sha256(CONFIG).hexdigest())
        self.assertNotIn("SYNTHETIC_SECRET_VALUE", repr(finding))
        scan_argv, scan_stdin, _ = runner.calls[1]
        self.assertEqual(scan_stdin, raw)
        self.assertNotIn(raw.decode(), " ".join(scan_argv))
        self.assertIn("--report-path=-", scan_argv)
        self.assertIn("--redact=100", scan_argv)
        self.assertIn("--ignore-gitleaks-allow", scan_argv)

    def test_clean_exit_with_findings_is_still_a_finding(self):
        report = b'[{"RuleID":"synthetic-rule","StartLine":1}]'
        result = screen_candidate(candidate(), make_adapter(FakeRunner(ProcessResult(0, report))))
        self.assertEqual(result.status, ScreeningStatus.FINDING)

    def test_malformed_output_and_inconsistent_exit_are_scanner_errors(self):
        for response in (ProcessResult(0, b"not json"), ProcessResult(1, b"[]"),
                         ProcessResult(2, b"[]")):
            with self.subTest(response=response):
                result = screen_candidate(candidate(), make_adapter(FakeRunner(response)))
                self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)

    def test_timeout_crash_and_output_overflow_are_scanner_errors(self):
        cases = (ProcessResult(0, b"", timed_out=True),
                 ProcessResult(0, b"", crashed=True),
                 ProcessResult(0, b"", output_overflow=True))
        for response in cases:
            runner = FakeRunner(response)
            result = screen_candidate(candidate(), make_adapter(runner))
            self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
            self.assertNotEqual(result.status, ScreeningStatus.CLEAN)
        oversized = FakeRunner(ProcessResult(0, b"x" * 8193))
        result = screen_candidate(candidate(), make_adapter(oversized))
        self.assertEqual(result.error_code, "scanner_output_overflow")

    def test_version_mismatch_is_scanner_error(self):
        result = screen_candidate(candidate(), make_adapter(FakeRunner(version="0.0.0")))
        self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(result.error_code, "scanner_version_mismatch")

    def test_version_match_uses_no_candidate_input(self):
        runner = FakeRunner()
        raw = candidate("SYNTHETIC-CANDIDATE-BYTES")
        result = screen_candidate(raw, make_adapter(runner))
        self.assertEqual(result.status, ScreeningStatus.CLEAN)
        self.assertEqual(runner.calls[0][1], b"")
        self.assertEqual(runner.calls[0][0], (PIN.executable, "version"))

    def test_missing_and_malformed_version_responses_fail_closed(self):
        for response, code in ((b"", "scanner_version_response_missing"),
                               (b"not a version", "scanner_version_response_malformed"),
                               (b"gitleaks version \xff", "scanner_version_response_malformed")):
            class VersionRunner(FakeRunner):
                def run(self, argv, *, stdin, timeout_seconds, max_output_bytes,
                        expected_binary_sha256, expected_configuration_sha256,
                        expected_ignore_sha256, expected_executable,
                        expected_configuration_path, expected_ignore_path):
                    self.calls.append((argv, stdin, timeout_seconds))
                    return ProcessResult(0, response)
            result = screen_candidate(candidate(), make_adapter(VersionRunner()))
            self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
            self.assertEqual(result.error_code, code)

    def test_binary_checksum_mismatch_is_scanner_error(self):
        adapter = GitleaksAdapter(PIN, FakeRunner(), binary_reader=lambda _: b"wrong",
                                  configuration_reader=lambda _: CONFIG,
                                  ignore_reader=lambda _: IGNORE, timeout_seconds=3,
                                  max_output_bytes=8192)
        result = screen_candidate(candidate(), adapter)
        self.assertEqual(result.error_code, "scanner_checksum_mismatch")

    def test_configuration_mismatch_is_scanner_error_before_process(self):
        runner = FakeRunner()
        adapter = GitleaksAdapter(PIN, runner, binary_reader=lambda _: BINARY,
                                  configuration_reader=lambda _: b"wrong",
                                  ignore_reader=lambda _: IGNORE, timeout_seconds=3,
                                  max_output_bytes=8192)
        result = screen_candidate(candidate(), adapter)
        self.assertEqual(result.error_code, "scanner_configuration_mismatch")
        self.assertEqual(runner.calls, [])

    def test_runner_crash_exception_is_sanitized(self):
        raw = candidate("National ID: 00000000 SYNTHETIC_CANDIDATE_MATERIAL")
        secret = "SYNTHETIC_SECRET_MATERIAL"
        class CrashingRunner:
            def __init__(self):
                self.calls = []

            def run(self, argv, *, stdin, timeout_seconds, max_output_bytes,
                    expected_binary_sha256, expected_configuration_sha256,
                    expected_ignore_sha256, expected_executable,
                    expected_configuration_path, expected_ignore_path):
                self.calls.append((argv, stdin))
                if len(self.calls) == 1:
                    return ProcessResult(0, b"gitleaks version 8.25.0")
                raise RuntimeError(secret + " " + raw.decode("utf-8") + repr(stdin))
        runner = CrashingRunner()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = screen_candidate(raw, make_adapter(runner))
        self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(result.error_code, "scanner_runner_failure")
        self.assertIn("identity_identifier", {finding.rule_id for finding in result.findings})
        self.assertEqual(result.gitleaks_identity,
                         "gitleaks/8.25.0@sha256:" + hashlib.sha256(BINARY).hexdigest())
        self.assertEqual(runner.calls[0], ((PIN.executable, "version"), b""))
        self.assertEqual(runner.calls[1][1], raw)
        self.assertEqual(runner.calls[1][0][-1], "stdin")
        self.assertNotIn(raw.decode(), repr(result))
        captured = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(captured, "")
        self.assertNotIn(raw.decode(), captured)
        self.assertNotIn(secret, repr(result) + captured)

    def test_privacy_configuration_digest_tracks_rule_ids_and_patterns(self):
        original = _privacy_configuration_digest()
        changed_rule = (("changed-rule", _PRIVACY_RULE_PATTERNS[0][1]),) + _PRIVACY_RULE_PATTERNS[1:]
        changed_pattern = (("personal_email", re.compile(_EMAIL.pattern + "x", _EMAIL.flags)),) + _PRIVACY_RULE_PATTERNS[1:]
        self.assertEqual(original, PRIVACY_CONFIG_ID)
        self.assertNotEqual(original, _privacy_configuration_digest(changed_rule))
        self.assertNotEqual(original, _privacy_configuration_digest(changed_pattern))
        changed_fields = ("title", "summary", "highlights", "technologies",
                          "evidence", "description")
        changed_networks = ("10.0.0.0/8", "172.16.0.0/12",
                            "192.168.0.0/16", "100.64.0.0/10")
        self.assertNotEqual(original, _privacy_configuration_digest(fields=changed_fields))
        self.assertNotEqual(
            original,
            _privacy_configuration_digest(private_ipv4_networks=changed_networks),
        )

    def test_scanner_response_is_validated(self):
        scanner_identity = (
            "gitleaks/8.25.0@sha256:" + hashlib.sha256(BINARY).hexdigest()
        )
        configuration_identity = hashlib.sha256(CONFIG).hexdigest()
        metadata = GitleaksScanMetadata(
            scanner_identity, configuration_identity, PIN.version,
        )

        class ResponseAdapter:
            pin = PIN

            def __init__(self, response):
                self.response = response

            def scan(self, _raw):
                return self.response

        raw = candidate()
        digest = hashlib.sha256(raw).hexdigest()
        good = ScreeningFinding(
            "gitleaks", "8.25.0", "test-rule", "line:1", "secret",
            digest, scanner_identity, configuration_identity,
        )
        mismatched = ScreeningFinding(
            "gitleaks", "8.25.0", "test-rule", "line:1", "secret",
            "0" * 64, scanner_identity, configuration_identity,
        )

        forged = object.__new__(GitleaksScanResult)
        object.__setattr__(forged, "findings", (object(),))
        object.__setattr__(forged, "metadata", metadata)

        invalid_responses = ([good], object(), forged,
                             GitleaksScanResult((mismatched,), metadata))
        for response in invalid_responses:
            with self.subTest(response_type=type(response).__name__):
                result = screen_candidate(raw, ResponseAdapter(response))
                self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
                self.assertEqual(result.error_code, "scanner_response_invalid")

        unavailable = screen_candidate(
            raw, ResponseAdapter(GitleaksScanResult((), None))
        )
        self.assertEqual(unavailable.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(unavailable.error_code, "scanner_identity_unverified")
        self.assertIsNone(unavailable.gitleaks_identity)

        wrong_metadata = GitleaksScanMetadata(
            "gitleaks/8.25.0@sha256:" + ("1" * 64),
            configuration_identity, PIN.version,
        )
        mismatched_pin = screen_candidate(
            raw, ResponseAdapter(GitleaksScanResult((), wrong_metadata))
        )
        self.assertEqual(mismatched_pin.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(mismatched_pin.error_code, "scanner_identity_mismatch")

        malformed_metadata = object.__new__(GitleaksScanMetadata)
        forged_metadata_result = object.__new__(GitleaksScanResult)
        object.__setattr__(forged_metadata_result, "findings", ())
        object.__setattr__(forged_metadata_result, "metadata", malformed_metadata)
        malformed = screen_candidate(raw, ResponseAdapter(forged_metadata_result))
        self.assertEqual(malformed.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(malformed.error_code, "scanner_identity_mismatch")

        missing_metadata_result = object.__new__(GitleaksScanResult)
        object.__setattr__(missing_metadata_result, "findings", ())
        malformed = screen_candidate(raw, ResponseAdapter(missing_metadata_result))
        self.assertEqual(malformed.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(malformed.error_code, "scanner_response_invalid")

    def test_privacy_metadata_only_exists_after_privacy_screening(self):
        oversized = screen_candidate(b" " * 1_048_577, make_adapter())
        self.assertEqual(oversized.status, ScreeningStatus.SCANNER_ERROR)
        self.assertIsNone(oversized.privacy_detector_id)
        self.assertIsNone(oversized.privacy_configuration_identity)

        malformed = screen_candidate(b"not valid candidate JSON", make_adapter())
        self.assertEqual(malformed.status, ScreeningStatus.SCANNER_ERROR)
        self.assertIsNone(malformed.privacy_detector_id)
        self.assertIsNone(malformed.privacy_configuration_identity)

        scanner_error = screen_candidate(
            candidate(),
            make_adapter(FakeRunner(ProcessResult(0, b"malformed scanner output"))),
        )
        self.assertEqual(scanner_error.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(scanner_error.privacy_detector_id, "portfolio-field-privacy")
        self.assertIsNotNone(scanner_error.privacy_configuration_identity)
        self.assertIsNotNone(scanner_error.gitleaks_identity)

    def test_screening_result_rejects_finding_for_another_candidate(self):
        raw = candidate()
        digest = hashlib.sha256(raw).hexdigest()
        other_digest = "0" * 64
        scanner_identity = (
            "gitleaks/8.25.0@sha256:" + hashlib.sha256(BINARY).hexdigest()
        )
        configuration_identity = hashlib.sha256(CONFIG).hexdigest()
        finding = ScreeningFinding(
            "gitleaks", "8.25.0", "test-rule", "line:1", "secret",
            other_digest, scanner_identity, configuration_identity,
        )
        with self.assertRaises(ValueError):
            ScreeningResult(
                ScreeningStatus.FINDING, digest, (finding,),
                gitleaks_identity=scanner_identity,
                gitleaks_configuration_identity=configuration_identity,
                privacy_detector_id="portfolio-field-privacy",
                privacy_detector_version="1.0.0",
                privacy_configuration_identity=PRIVACY_CONFIG_ID,
            )

    def test_interleaved_scans_keep_invocation_specific_metadata(self):
        scan_entered = threading.Event()
        release_scan = threading.Event()

        class InterleavingRunner:
            def run(self, argv, *, stdin, timeout_seconds, max_output_bytes,
                    expected_binary_sha256, expected_configuration_sha256,
                    expected_ignore_sha256, expected_executable,
                    expected_configuration_path, expected_ignore_path):
                if argv[-1] == "version":
                    if threading.current_thread().name == "screen-good":
                        return ProcessResult(0, b"gitleaks version 8.25.0")
                    return ProcessResult(0, b"not a valid version")

                scan_entered.set()
                if not release_scan.wait(5):
                    raise RuntimeError("synthetic scan synchronization timeout")
                return ProcessResult(0, b"[]")

        adapter = make_adapter(InterleavingRunner())
        results = {}
        failures = {}

        def run_screening(key):
            try:
                results[key] = screen_candidate(candidate(), adapter)
            except Exception as error:
                failures[key] = type(error).__name__

        good_thread = threading.Thread(
            target=run_screening, args=("good",), name="screen-good",
        )
        bad_thread = threading.Thread(
            target=run_screening, args=("bad",), name="screen-bad",
        )

        good_thread.start()
        self.assertTrue(scan_entered.wait(5), "good scan did not reach scanner")
        bad_thread.start()
        bad_thread.join(5)
        release_scan.set()
        good_thread.join(5)

        self.assertFalse(good_thread.is_alive())
        self.assertFalse(bad_thread.is_alive())
        self.assertEqual(failures, {})
        self.assertEqual(results["good"].status, ScreeningStatus.CLEAN)
        self.assertEqual(
            results["good"].gitleaks_identity,
            "gitleaks/8.25.0@sha256:" + hashlib.sha256(BINARY).hexdigest(),
        )
        self.assertEqual(results["bad"].status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(
            results["bad"].error_code, "scanner_version_response_malformed",
        )

    def test_toml_allowlist_structure_and_harmless_text(self):
        cases = (
            ('[allowlist]\npaths = [".*"]\n', True),
            ('[allowlists]\npaths = [".*"]\n', True),
            ('title = "allowlist" # allowlists\n', False),
            ('# allowlist\ntitle = "fixture"\n', False),
            ('[tool]\n[tool.allowlist]\ncommits = ["abc"]\n', True),
            ('[extend]\nuseDefault = true\n', True),
            ('[extend]\npath = "another-config.toml"\n', True),
            ('[extend]\nuseDefault = false\npath = ""\n', False),
            ('title = "unterminated', "malformed"),
            ('title = 1\ntitle = 2', "malformed"),
        )
        for config, expected in cases:
            with self.subTest(config=config):
                config_bytes = config.encode()
                pin = GitleaksPin(PIN.executable, PIN.version, PIN.binary_sha256,
                                  PIN.configuration_path, hashlib.sha256(config_bytes).hexdigest(),
                                  PIN.ignore_path, PIN.ignore_sha256)
                adapter = GitleaksAdapter(
                    pin, FakeRunner(), binary_reader=lambda _path: BINARY,
                    configuration_reader=lambda _path, value=config_bytes: value,
                    ignore_reader=lambda _path: IGNORE, timeout_seconds=3,
                    max_output_bytes=8192)
                result = screen_candidate(candidate(), adapter)
                if expected == "malformed":
                    self.assertEqual(result.error_code, "scanner_configuration_malformed")
                elif expected:
                    self.assertEqual(result.error_code, "scanner_suppressions_forbidden")
                else:
                    self.assertEqual(result.status, ScreeningStatus.CLEAN)
        with self.assertRaises(ScreeningOperationalError) as error:
            _has_allowlist(None)
        self.assertEqual(error.exception.code, "scanner_configuration_malformed")

    def test_pin_paths_validate_nulls_whitespace_and_types(self):
        for index in (0, 3, 5):
            values = [PIN.executable, PIN.version, PIN.binary_sha256, PIN.configuration_path,
                      PIN.configuration_sha256, PIN.ignore_path, PIN.ignore_sha256]
            values[index] = values[index] + "\x00"
            with self.subTest(index=index), self.assertRaises(ValueError):
                GitleaksPin(*values)
            values[index] = " " + values[index].replace("\x00", "")
            with self.subTest(index=index, whitespace=True), self.assertRaises(ValueError):
                GitleaksPin(*values)
        for index in (0, 3, 5):
            values = [PIN.executable, PIN.version, PIN.binary_sha256, PIN.configuration_path,
                      PIN.configuration_sha256, PIN.ignore_path, PIN.ignore_sha256]
            values[index] = None
            with self.subTest(index=index, invalid_type=True), self.assertRaises(ValueError):
                GitleaksPin(*values)

    def test_missing_executable_and_missing_resource_policies_fail_closed(self):
        adapter = GitleaksAdapter(PIN, FakeRunner(), binary_reader=lambda _: (_ for _ in ()).throw(OSError("private")),
                                  configuration_reader=lambda _: CONFIG, ignore_reader=lambda _: IGNORE,
                                  timeout_seconds=3, max_output_bytes=8192)
        self.assertEqual(screen_candidate(candidate(), adapter).status, ScreeningStatus.SCANNER_ERROR)
        adapter = make_adapter(timeout_seconds=None)
        self.assertEqual(screen_candidate(candidate(), adapter).error_code, "scanner_timeout_policy_missing")
        for invalid_timeout in (float("nan"), float("inf"), float("-inf"), 0, -1, "3"):
            with self.subTest(timeout=invalid_timeout):
                result = screen_candidate(candidate(), make_adapter(timeout_seconds=invalid_timeout))
                self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
                self.assertEqual(result.error_code, "scanner_timeout_policy_missing")
        adapter = make_adapter(max_output_bytes=None)
        self.assertEqual(screen_candidate(candidate(), adapter).error_code, "scanner_output_limit_missing")

    def test_allowlist_configuration_and_nonempty_ignore_are_rejected(self):
        config = b'title = "fixture"\n[allowlist]\npaths = [".*"]\n'
        pin = GitleaksPin("gitleaks-fixture", "8.25.0", hashlib.sha256(BINARY).hexdigest(),
                          "central-gitleaks.toml", hashlib.sha256(config).hexdigest(),
                          "central-empty-gitleaksignore", hashlib.sha256(IGNORE).hexdigest())
        adapter = GitleaksAdapter(pin, FakeRunner(), binary_reader=lambda _: BINARY,
                                  configuration_reader=lambda _: config, ignore_reader=lambda _: IGNORE,
                                  timeout_seconds=3, max_output_bytes=8192)
        self.assertEqual(screen_candidate(candidate(), adapter).error_code, "scanner_suppressions_forbidden")
        adapter = GitleaksAdapter(PIN, FakeRunner(), binary_reader=lambda _: BINARY,
                                  configuration_reader=lambda _: CONFIG,
                                  ignore_reader=lambda _: b"synthetic suppression",
                                  timeout_seconds=3, max_output_bytes=8192)
        self.assertEqual(screen_candidate(candidate(), adapter).error_code, "scanner_ignore_policy_mismatch")

    def test_privacy_findings_cover_required_categories(self):
        cases = (
            ("Contact: synthetic.person@example.invalid", "personal_email"),
            ("Phone: +254712345678", "personal_phone"),
            ("National ID: 00000000", "identity_identifier"),
            ("SSN: 000-00-0000", "identity_identifier"),
            ("KRA PIN: A000000000Z", "tax_identifier"),
            ("Customer email: synthetic.person@example.invalid", "customer_record"),
            ("Customer name: Synthetic User", "customer_record"),
            ("Confidential customer invoice record", "confidential_business_record"),
            ("Customer account email: synthetic.person@example.invalid", "customer_identifiable_information"),
            ("Invoice for customer: INV-1042", "customer_business_record"),
            ("Non-public pricing figures for Q4", "confidential_business_detail"),
            ("Internal host: app.service.internal", "nonpublic_infrastructure"),
            ("Private endpoint 172.20.3.4", "nonpublic_infrastructure"),
            ("Internal hostname: db01.corp", "internal_configuration"),
            ("Private endpoint 10.20.30.40", "nonpublic_infrastructure"),
        )
        for value, expected_rule in cases:
            with self.subTest(rule=expected_rule):
                result = screen_candidate(candidate(value), make_adapter())
                self.assertEqual(result.status, ScreeningStatus.FINDING)
                self.assertIn(expected_rule, {finding.rule_id for finding in result.findings})

    def test_invalid_private_ipv4_does_not_match_and_public_engineering_passes(self):
        for value in ("Private endpoint 10.999.30.40", "Private endpoint 192.168.1.256",
                      "Documented API uses 203.0.113.10 in an example."):
            with self.subTest(value=value):
                result = screen_candidate(candidate(value), make_adapter())
                self.assertEqual(result.status, ScreeningStatus.CLEAN)

    def test_privacy_adversarial_contexts_without_explicit_labels(self):
        cases = (
            ("Invoice INV-2026-0042 total KES 125,000 was paid", "customer_business_record"),
            ("Revenue figures: KES 4,200,000", "confidential_business_detail"),
            ("DATABASE_URL=postgres://db-prod-cluster.internal/app", "internal_configuration"),
            ("Connect to db-prod-cluster-01 for the service", "nonpublic_infrastructure"),
        )
        for value, rule in cases:
            with self.subTest(rule=rule):
                result = screen_candidate(candidate(value), make_adapter())
                self.assertEqual(result.status, ScreeningStatus.FINDING)
                self.assertIn(rule, {finding.rule_id for finding in result.findings})

    def test_public_financial_api_and_hostname_descriptions_remain_clean(self):
        cases = (
            "The public API exposes a documented payment-status endpoint.",
            "Revenue reporting supports currency formatting in the public demo.",
            "The example host api.example.com serves static documentation.",
            "Database configuration is documented with placeholder values.",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(screen_candidate(candidate(value), make_adapter()).status,
                                 ScreeningStatus.CLEAN)

    def test_generic_public_engineering_description_passes(self):
        raw = candidate("Documented API pagination for the public project overview.")
        result = screen_candidate(raw, make_adapter())
        self.assertEqual(result.status, ScreeningStatus.CLEAN)

    def test_ambiguous_sensitive_markers_block(self):
        raw = candidate("Internal host: service.internal")
        result = screen_candidate(raw, make_adapter())
        self.assertEqual(result.status, ScreeningStatus.FINDING)
        self.assertEqual(result.findings[0].location, "$.title")

    def test_raw_candidate_never_appears_in_logs_or_failure_messages(self):
        raw = candidate("SYNTHETIC_PRIVATE_VALUE")
        runner = FakeRunner(ProcessResult(0, b"malformed-output"))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = screen_candidate(raw, make_adapter(runner))
        combined = stdout.getvalue() + stderr.getvalue() + repr(result)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(raw.decode(), combined)
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", combined)

    def test_scanner_error_never_becomes_clean_and_result_is_immutable(self):
        result = screen_candidate(candidate(), make_adapter(FakeRunner(ProcessResult(0, b"broken"))))
        self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
        with self.assertRaises((AttributeError, TypeError)):
            result.status = ScreeningStatus.CLEAN

    def test_existing_one_mib_candidate_limit_is_enforced(self):
        raw = b" " * (1_048_577)
        result = screen_candidate(raw, make_adapter())
        self.assertEqual(result.status, ScreeningStatus.SCANNER_ERROR)
        self.assertEqual(result.error_code, "candidate_input_too_large")


if __name__ == "__main__":
    unittest.main()
