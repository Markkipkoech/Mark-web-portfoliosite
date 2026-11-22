"""Linux AMD64 process boundary for the pinned Gitleaks scanner."""

from __future__ import annotations

import hashlib
import math
import os
import platform
import select
import signal
import stat
import subprocess
import tempfile
import time
from typing import Tuple

from candidate_screening import ProcessResult


class RunnerPolicyError(Exception):
    """Sanitized runner policy or pinned-asset failure."""


class LinuxAmd64ProcessRunner:
    """Execute only the exact pinned assets, with bounded streaming I/O."""

    _CHUNK_SIZE = 65536
    _EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

    @staticmethod
    def _require_linux_amd64() -> None:
        if platform.system() != "Linux" or platform.machine().lower() not in (
            "x86_64", "amd64",
        ):
            raise RunnerPolicyError("unsupported_scanner_platform")
        if not os.path.isdir("/proc/self/fd"):
            raise RunnerPolicyError("scanner_descriptor_execution_unavailable")

    @staticmethod
    def _open_pinned(path: str, expected_digest: str, *, executable: bool = False) -> int:
        if not isinstance(path, str) or not path or "\x00" in path:
            raise RunnerPolicyError("scanner_asset_path_invalid")
        if (not isinstance(expected_digest, str) or len(expected_digest) != 64
                or any(ch not in "0123456789abcdef" for ch in expected_digest)):
            raise RunnerPolicyError("scanner_asset_digest_invalid")

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RunnerPolicyError("scanner_asset_not_regular_file")
            if executable and not (info.st_mode & 0o111):
                raise RunnerPolicyError("scanner_executable_not_executable")

            digest = hashlib.sha256()
            os.lseek(fd, 0, os.SEEK_SET)
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            os.lseek(fd, 0, os.SEEK_SET)

            if digest.hexdigest() != expected_digest:
                raise RunnerPolicyError("scanner_asset_digest_mismatch")
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _validate_argv(argv: Tuple[str, ...], executable: str,
                       configuration: str, ignore: str) -> Tuple[str, ...]:
        if not isinstance(argv, tuple) or not argv:
            raise RunnerPolicyError("scanner_arguments_invalid")
        if any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
            raise RunnerPolicyError("scanner_arguments_invalid")
        if argv[0] != executable:
            raise RunnerPolicyError("scanner_executable_path_mismatch")

        rewritten = list(argv)
        for option, expected, descriptor_name in (
            ("--config", configuration, "configuration"),
            ("--gitleaks-ignore-path", ignore, "ignore"),
        ):
            positions = [i for i, value in enumerate(rewritten) if value == option]
            if len(positions) != 1:
                raise RunnerPolicyError("scanner_arguments_invalid")
            index = positions[0]
            if index + 1 >= len(rewritten) or rewritten[index + 1] != expected:
                raise RunnerPolicyError("scanner_asset_argument_mismatch")
            # The caller replaces this with the descriptor path after opening.
            rewritten[index + 1] = descriptor_name
        return tuple(rewritten)

    @staticmethod
    def _kill_group(process: subprocess.Popen) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def run(
        self,
        argv: Tuple[str, ...],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
        expected_binary_sha256: str,
        expected_configuration_sha256: str,
        expected_ignore_sha256: str,
        expected_executable: str,
        expected_configuration_path: str,
        expected_ignore_path: str,
    ) -> ProcessResult:
        self._require_linux_amd64()

        if not isinstance(stdin, bytes):
            raise RunnerPolicyError("scanner_input_invalid")
        try:
            valid_timeout = (
                not isinstance(timeout_seconds, bool)
                and isinstance(timeout_seconds, (int, float))
                and math.isfinite(timeout_seconds)
                and timeout_seconds > 0
            )
        except (OverflowError, TypeError, ValueError):
            valid_timeout = False

        if not valid_timeout:
            raise RunnerPolicyError("scanner_timeout_policy_invalid")
        if type(max_output_bytes) is not int or max_output_bytes <= 0:
            raise RunnerPolicyError("scanner_output_limit_invalid")

        # Validate argument/path binding before opening or launching anything.
        rewritten = self._validate_argv(
            argv, expected_executable,
            expected_configuration_path, expected_ignore_path,
        )

        executable_fd = configuration_fd = ignore_fd = None
        process = None
        output = bytearray()
        timed_out = False
        overflow = False

        try:
            executable_fd = self._open_pinned(
                expected_executable, expected_binary_sha256, executable=True,
            )
            configuration_fd = self._open_pinned(
                expected_configuration_path, expected_configuration_sha256,
            )
            ignore_fd = self._open_pinned(
                expected_ignore_path, expected_ignore_sha256,
            )
            if expected_ignore_sha256 != self._EMPTY_SHA256 or os.fstat(ignore_fd).st_size != 0:
                raise RunnerPolicyError("scanner_ignore_policy_not_empty")

            executable_fd_path = "/proc/self/fd/{}".format(executable_fd)
            configuration_fd_path = "/proc/self/fd/{}".format(configuration_fd)
            ignore_fd_path = "/proc/self/fd/{}".format(ignore_fd)

            child_argv = list(rewritten)
            child_argv[0] = executable_fd_path
            for option, descriptor_path in (
                ("--config", configuration_fd_path),
                ("--gitleaks-ignore-path", ignore_fd_path),
            ):
                option_index = child_argv.index(option)
                child_argv[option_index + 1] = descriptor_path

            with tempfile.TemporaryDirectory(prefix="portfolio-gitleaks-") as workdir:
                environment = {
                    "PATH": "/usr/bin:/bin",
                    "HOME": workdir,
                    "TMPDIR": workdir,
                    "LANG": "C",
                    "LC_ALL": "C",
                }
                process = subprocess.Popen(
                    child_argv,
                    executable=executable_fd_path,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    cwd=workdir,
                    env=environment,
                    close_fds=True,
                    pass_fds=(executable_fd, configuration_fd, ignore_fd),
                    shell=False,
                    start_new_session=True,
                    bufsize=0,
                )

                assert process.stdin is not None
                assert process.stdout is not None
                stdin_fd = process.stdin.fileno()
                stdout_fd = process.stdout.fileno()
                os.set_blocking(stdin_fd, False)
                os.set_blocking(stdout_fd, False)

                input_view = memoryview(stdin)
                input_offset = 0
                stdin_open = True
                stdout_open = True
                deadline = time.monotonic() + float(timeout_seconds)

                if not input_view:
                    process.stdin.close()
                    stdin_open = False

                while stdout_open or stdin_open or process.poll() is None:
                    if process.poll() is not None and stdin_open:
                        process.stdin.close()
                        stdin_open = False

                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0:
                        timed_out = True
                        self._kill_group(process)
                        break

                    read_fds = [stdout_fd] if stdout_open else []
                    write_fds = [stdin_fd] if stdin_open else []
                    readable, writable, _ = select.select(
                        read_fds, write_fds, [], min(remaining_time, 0.1),
                    )

                    if stdin_open and stdin_fd in writable:
                        try:
                            written = os.write(
                                stdin_fd,
                                input_view[input_offset:input_offset + self._CHUNK_SIZE],
                            )
                            input_offset += written
                            if input_offset >= len(input_view):
                                process.stdin.close()
                                stdin_open = False
                        except BrokenPipeError:
                            process.stdin.close()
                            stdin_open = False

                    if stdout_open and stdout_fd in readable:
                        chunk = os.read(stdout_fd, self._CHUNK_SIZE)
                        if not chunk:
                            process.stdout.close()
                            stdout_open = False
                        elif len(output) + len(chunk) > max_output_bytes:
                            allowed = max_output_bytes - len(output)
                            if allowed > 0:
                                output.extend(chunk[:allowed])
                            overflow = True
                            self._kill_group(process)
                            break
                        else:
                            output.extend(chunk)

                if timed_out or overflow:
                    if stdin_open:
                        process.stdin.close()
                        stdin_open = False
                    self._kill_group(process)

                try:
                    returncode = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._kill_group(process)
                    returncode = process.wait()

                # Close the pipe without waiting for descendants to release it.
                if stdout_open:
                    process.stdout.close()
                    stdout_open = False

                return ProcessResult(
                    returncode=returncode,
                    stdout=bytes(output),
                    timed_out=timed_out,
                    crashed=(returncode < 0 and not timed_out and not overflow),
                    output_overflow=overflow,
                )
        finally:
            if process is not None and process.poll() is None:
                self._kill_group(process)
                process.wait()
            for fd in (executable_fd, configuration_fd, ignore_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
