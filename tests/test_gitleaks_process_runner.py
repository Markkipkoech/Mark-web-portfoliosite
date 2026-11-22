import hashlib
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "portfolio-data" / "scripts"))

from gitleaks_process_runner import (  # noqa: E402
    LinuxAmd64ProcessRunner,
    RunnerPolicyError,
)


class RunnerPolicyTests(unittest.TestCase):
    def test_non_linux_platform_is_rejected_before_file_access(self):
        runner = LinuxAmd64ProcessRunner()
        with patch("gitleaks_process_runner.platform.system", return_value="Windows"):
            with self.assertRaisesRegex(
                RunnerPolicyError, "unsupported_scanner_platform",
            ):
                runner.run(
                    ("gitleaks", "version"),
                    stdin=b"",
                    timeout_seconds=1,
                    max_output_bytes=100,
                    expected_binary_sha256="0" * 64,
                    expected_configuration_sha256="0" * 64,
                    expected_ignore_sha256=hashlib.sha256(b"").hexdigest(),
                    expected_executable="gitleaks",
                    expected_configuration_path="config.toml",
                    expected_ignore_path="ignore",
                )

    def test_invalid_timeouts_are_rejected_before_file_access(self):
        runner = LinuxAmd64ProcessRunner()
        invalid_timeouts = (
            ("nan", float("nan")),
            ("positive infinity", float("inf")),
            ("negative infinity", float("-inf")),
            ("oversized integer", 10 ** 1000),
        )

        with patch.object(runner, "_require_linux_amd64"):
            for label, timeout in invalid_timeouts:
                with self.subTest(timeout=label):
                    with self.assertRaisesRegex(
                        RunnerPolicyError, "scanner_timeout_policy_invalid",
                    ):
                        runner.run(
                            (
                                "gitleaks", "--config", "config.toml",
                                "--gitleaks-ignore-path", "ignore", "stdin",
                            ),
                            stdin=b"",
                            timeout_seconds=timeout,
                            max_output_bytes=100,
                            expected_binary_sha256="0" * 64,
                            expected_configuration_sha256="0" * 64,
                            expected_ignore_sha256=hashlib.sha256(b"").hexdigest(),
                            expected_executable="gitleaks",
                            expected_configuration_path="config.toml",
                            expected_ignore_path="ignore",
                        )

    def test_argument_paths_must_match_pins(self):
        with self.assertRaisesRegex(
            RunnerPolicyError, "scanner_asset_argument_mismatch",
        ):
            LinuxAmd64ProcessRunner._validate_argv(
                (
                    "gitleaks", "--config", "other.toml",
                    "--gitleaks-ignore-path", "ignore", "stdin",
                ),
                "gitleaks", "config.toml", "ignore",
            )

    def test_duplicate_config_option_is_rejected(self):
        with self.assertRaisesRegex(
            RunnerPolicyError, "scanner_arguments_invalid",
        ):
            LinuxAmd64ProcessRunner._validate_argv(
                (
                    "gitleaks", "--config", "config.toml",
                    "--config", "config.toml",
                    "--gitleaks-ignore-path", "ignore", "stdin",
                ),
                "gitleaks", "config.toml", "ignore",
            )


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64"),
    "real process integration tests require Linux AMD64",
)
class LinuxRunnerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binary = self.root / "scanner"
        self.config = self.root / "config.toml"
        self.ignore = self.root / "ignore"
        self.config.write_text('title = "test"\n', encoding="utf-8")
        self.ignore.write_bytes(b"")

    def tearDown(self):
        self.temp.cleanup()

    def write_scanner(self, body):
        self.binary.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        self.binary.chmod(0o700)

    def invoke(self, *, stdin=b"candidate fixture", timeout=2, limit=8192):
        binary_bytes = self.binary.read_bytes()
        config_bytes = self.config.read_bytes()
        ignore_bytes = self.ignore.read_bytes()
        argv = (
            str(self.binary),
            "--no-banner",
            "--config", str(self.config),
            "--gitleaks-ignore-path", str(self.ignore),
            "stdin",
        )
        return LinuxAmd64ProcessRunner().run(
            argv,
            stdin=stdin,
            timeout_seconds=timeout,
            max_output_bytes=limit,
            expected_binary_sha256=hashlib.sha256(binary_bytes).hexdigest(),
            expected_configuration_sha256=hashlib.sha256(config_bytes).hexdigest(),
            expected_ignore_sha256=hashlib.sha256(ignore_bytes).hexdigest(),
            expected_executable=str(self.binary),
            expected_configuration_path=str(self.config),
            expected_ignore_path=str(self.ignore),
        )

    def test_runs_pinned_executable_with_stdin_and_bounded_stdout(self):
        self.write_scanner('cat >/dev/null\nprintf "[]"\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"[]")
        self.assertFalse(result.timed_out)
        self.assertFalse(result.crashed)
        self.assertFalse(result.output_overflow)

    def test_binary_digest_mismatch_prevents_execution(self):
        self.write_scanner('printf "executed"\n')
        with self.assertRaisesRegex(
            RunnerPolicyError, "scanner_asset_digest_mismatch",
        ):
            LinuxAmd64ProcessRunner().run(
                (str(self.binary), "--config", str(self.config),
                 "--gitleaks-ignore-path", str(self.ignore), "stdin"),
                stdin=b"",
                timeout_seconds=1,
                max_output_bytes=100,
                expected_binary_sha256="0" * 64,
                expected_configuration_sha256=hashlib.sha256(
                    self.config.read_bytes()
                ).hexdigest(),
                expected_ignore_sha256=hashlib.sha256(b"").hexdigest(),
                expected_executable=str(self.binary),
                expected_configuration_path=str(self.config),
                expected_ignore_path=str(self.ignore),
            )

    def test_output_limit_terminates_scanner(self):
        self.write_scanner('head -c 100000 /dev/zero\n')
        result = self.invoke(limit=128)
        self.assertTrue(result.output_overflow)
        self.assertLessEqual(len(result.stdout), 128)

    def test_timeout_terminates_scanner(self):
        self.write_scanner('sleep 5\n')
        result = self.invoke(timeout=0.2)
        self.assertTrue(result.timed_out)


if __name__ == "__main__":
    unittest.main()
