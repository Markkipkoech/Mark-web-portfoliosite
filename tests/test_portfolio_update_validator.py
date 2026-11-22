import builtins
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "portfolio-data" / "scripts"))

import validate_portfolio_update as validator


class FakeSchemaError(Exception):
    pass


class FakeSchemaValidator:
    @staticmethod
    def check_schema(schema):
        return None

    def __init__(self, schema, format_checker=None):
        self.schema = schema

    def iter_errors(self, candidate):
        if isinstance(candidate, dict) and "extra_field" in candidate:
            yield type(
                "FakeValidationError",
                (),
                {
                    "absolute_path": [],
                    "validator": "additionalProperties",
                    "validator_value": False,
                    "instance": candidate,
                },
            )()


class PortfolioUpdateValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temporary_root = Path(self.temporary_directory.name)
        self.repo_root = self.temporary_root / "isolated-repository"
        self.data_root = self.repo_root / "portfolio-data"
        self.schema_path = self.data_root / "schemas" / "portfolio-update.schema.json"
        self.registry_path = self.data_root / "projects" / "registry.json"
        self.approved_dir = self.data_root / "updates" / "approved"
        self.schema_path.parent.mkdir(parents=True)
        self.registry_path.parent.mkdir(parents=True)
        self.approved_dir.mkdir(parents=True)

        source_data = REPOSITORY_ROOT / "portfolio-data"
        self.schema = json.loads(
            (source_data / "schemas" / "portfolio-update.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.registry = json.loads(
            (source_data / "projects" / "registry.json").read_text(
                encoding="utf-8"
            )
        )
        self._write_schema()
        self._write_registry()

        self.candidate = {
            "schema_version": "1.0",
            "project_id": "companyhub",
            "update_id": "isolated-test-update",
            "date": "2026-11-10",
            "category": "milestone",
            "title": "Test milestone",
            "summary": "A factual test summary.",
            "highlights": ["A verified test highlight."],
            "technologies": ["Python"],
            "evidence": ["https://github.com/example/project"],
            "destination": "engineering",
        }
        self.candidate_path = self.temporary_root / "candidate.json"

    def _write_schema(self):
        self.schema_path.write_text(json.dumps(self.schema), encoding="utf-8")

    def _write_registry(self):
        self.registry_path.write_text(json.dumps(self.registry), encoding="utf-8")

    def _write_candidate(self, value=None, raw=None):
        if raw is not None:
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            self.candidate_path.write_bytes(raw)
        else:
            candidate = self.candidate if value is None else value
            self.candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        return self.candidate_path

    def _run_cli(self, candidate_path=None, patch_import=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        candidate_path = candidate_path or self.candidate_path
        fake_script = self.repo_root / "portfolio-data" / "scripts" / "validator.py"

        with patch.object(validator, "__file__", str(fake_script)):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                if patch_import is None:
                    result = validator.main([str(candidate_path)])
                else:
                    with patch.object(builtins, "__import__", side_effect=patch_import):
                        result = validator.main([str(candidate_path)])
        return result, stdout.getvalue(), stderr.getvalue()

    def _assert_cli_rejected(self, candidate_path=None, message=None):
        code, stdout, stderr = self._run_cli(candidate_path)
        self.assertEqual(code, 1)
        self.assertIn("ERROR:", stderr)
        self.assertNotIn("Traceback", stderr)
        if message:
            self.assertIn(message, stderr)
        return stdout, stderr

    def _write_history(self, filename, value=None, raw=None):
        path = self.approved_dir / filename
        if raw is not None:
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            path.write_bytes(raw)
        else:
            path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_valid_candidate_passes(self):
        self._write_candidate()
        code, stdout, stderr = self._run_cli()
        self.assertEqual(code, 0, stderr)
        self.assertIn("may proceed to human review", stdout)
        self.assertIn("not approved for publication", stdout)

    def test_in_memory_api_reuses_validation_without_approved_history_check(self):
        self._write_history(
            "approved.json",
            {
                "project_id": self.candidate["project_id"],
                "update_id": self.candidate["update_id"],
            },
        )
        with patch.object(
            validator, "load_approved_pairs", side_effect=AssertionError
        ), patch.object(validator, "read_json", side_effect=AssertionError):
            errors = validator.validate_candidate_data(
                self.candidate,
                self.schema,
                self.registry,
                validator_class=FakeSchemaValidator,
                format_checker=object(),
                schema_error_type=FakeSchemaError,
            )
        self.assertEqual(errors, [])

    def test_in_memory_api_uses_real_draft_2020_12_schema_validator(self):
        from jsonschema import Draft202012Validator, FormatChecker, SchemaError

        valid_errors = validator.validate_candidate_data(
            self.candidate,
            self.schema,
            self.registry,
            validator_class=Draft202012Validator,
            format_checker=FormatChecker(),
            schema_error_type=SchemaError,
        )
        self.assertEqual(valid_errors, [])

        invalid_candidate = dict(self.candidate, unexpected_field="not allowed")
        invalid_errors = validator.validate_candidate_data(
            invalid_candidate,
            self.schema,
            self.registry,
            validator_class=Draft202012Validator,
            format_checker=FormatChecker(),
            schema_error_type=SchemaError,
        )
        self.assertTrue(
            any("not allowed by the schema" in error for error in invalid_errors),
            invalid_errors,
        )

    def test_in_memory_api_reports_schema_and_semantic_errors(self):
        candidate = dict(self.candidate, extra_field="not permitted")
        candidate["destination"] = "learning-journal"
        errors = validator.validate_candidate_data(
            candidate,
            self.schema,
            self.registry,
            validator_class=FakeSchemaValidator,
            format_checker=object(),
            schema_error_type=FakeSchemaError,
        )
        self.assertTrue(any("not allowed by the schema" in error for error in errors))
        self.assertTrue(
            any("not permitted for the selected project" in error for error in errors)
        )

    def test_registry_accepts_only_optional_positive_integer_repository_id(self):
        entry = self.registry["projects"]["companyhub"]
        entry["repository_id"] = 123456789
        self.assertTrue(any("exactly repository" in error for error in validator.validate_registry(self.registry)))
        validation_registry = validator.validate_pipeline_registry(self.registry)
        self.assertNotIn("repository_id", validation_registry["projects"]["companyhub"])
        for invalid_id in (0, -1, True, "123456789", 1.5):
            with self.subTest(repository_id=invalid_id):
                entry["repository_id"] = invalid_id
                with self.assertRaises(validator.ValidationConfigurationFailure):
                    validator.validate_pipeline_registry(self.registry)
        del entry["repository_id"]

    def test_registry_rejects_duplicate_numeric_repository_ids(self):
        self.registry["projects"]["companyhub"]["repository_id"] = 123456789
        self.registry["projects"]["backend-engineering-learning-journey"][
            "repository_id"
        ] = 123456789
        with self.assertRaises(validator.ValidationConfigurationFailure):
            validator.validate_pipeline_registry(self.registry)

    def test_in_memory_api_enforces_maximum_nesting_depth(self):
        candidate = self.candidate
        nested = candidate
        for _ in range(validator.MAX_JSON_DEPTH):
            nested["nested"] = {}
            nested = nested["nested"]
        errors = validator.validate_candidate_data(
            candidate,
            self.schema,
            self.registry,
            validator_class=FakeSchemaValidator,
            format_checker=object(),
            schema_error_type=FakeSchemaError,
        )
        self.assertTrue(any("nesting depth" in error for error in errors))

    def test_invalid_schema_fields_are_rejected(self):
        candidate = dict(self.candidate, repository_visibility="public")
        self._write_candidate(candidate)
        self._assert_cli_rejected(message="property not allowed")

    def test_unknown_project_is_rejected(self):
        candidate = dict(self.candidate, project_id="unknown-project")
        self._write_candidate(candidate)
        self._assert_cli_rejected()

    def test_disabled_project_is_rejected(self):
        self.registry["projects"]["companyhub"]["enabled"] = False
        self._write_registry()
        self._write_candidate()
        self._assert_cli_rejected(message="project selected by $.project_id is disabled")

    def test_unauthorized_destination_is_rejected(self):
        candidate = dict(self.candidate, destination="learning-journal")
        self._write_candidate(candidate)
        self._assert_cli_rejected(message="destination is not permitted")

    def test_duplicate_json_keys_are_rejected_at_top_level_and_nested(self):
        inputs = (
            '{"project_id":"companyhub","project_id":"companyhub"}',
            '{"metadata":{"same":1,"same":2}}',
        )
        for raw in inputs:
            with self.subTest(raw=raw):
                self._write_candidate(raw=raw)
                self._assert_cli_rejected(message="duplicate JSON object key")

    def test_duplicate_json_keys_are_rejected_in_all_json_inputs(self):
        self._write_candidate()
        duplicate_object = '{"first":1,"first":2}'

        for description, path in (
            ("schema", self.schema_path),
            ("registry", self.registry_path),
            ("history", self.approved_dir / "record.json"),
        ):
            with self.subTest(input_type=description):
                self._write_schema()
                self._write_registry()
                for history_file in self.approved_dir.glob("*.json"):
                    history_file.unlink()
                path.write_text(duplicate_object, encoding="utf-8")
                self._assert_cli_rejected(message="duplicate JSON object key")

    def test_nonstandard_json_constants_are_rejected_in_all_json_inputs(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            for description in ("candidate", "schema", "registry", "history"):
                with self.subTest(constant=constant, input_type=description):
                    self._write_schema()
                    self._write_registry()
                    for history_file in self.approved_dir.rglob("*.json"):
                        history_file.unlink()
                    self._write_candidate()
                    raw = '{{"probe":{}}}'.format(constant)
                    if description == "candidate":
                        self._write_candidate(raw=raw)
                    elif description == "schema":
                        self.schema_path.write_text(raw, encoding="utf-8")
                    elif description == "registry":
                        self.registry_path.write_text(raw, encoding="utf-8")
                    else:
                        self._write_history("record.json", raw=raw)
                    self._assert_cli_rejected(message="non-standard JSON constant")

    def test_malformed_json_is_rejected(self):
        self._write_candidate(raw="{")
        self._assert_cli_rejected(message="contains malformed JSON")

    def test_invalid_utf8_is_rejected(self):
        self._write_candidate(raw=b"\xff\xfe")
        self._assert_cli_rejected(message="is not valid UTF-8")

    def test_oversized_candidate_is_rejected(self):
        self._write_candidate(raw=b" " * (validator.MAX_JSON_BYTES + 1))
        self._assert_cli_rejected(message="maximum JSON input size")

    def test_excessive_json_nesting_is_rejected_without_traceback(self):
        raw = "[" * 2000 + "0" + "]" * 2000
        self._write_candidate(raw=raw)
        self._assert_cli_rejected(message="maximum JSON nesting depth")

    def test_size_limit_applies_to_each_json_input(self):
        oversized = b'{"padding":"' + b"x" * validator.MAX_JSON_BYTES + b'"}'
        for description in ("candidate", "schema", "registry", "history"):
            with self.subTest(input_type=description):
                self._write_schema()
                self._write_registry()
                for history_file in self.approved_dir.rglob("*.json"):
                    history_file.unlink()
                self._write_candidate()
                if description == "candidate":
                    self._write_candidate(raw=oversized)
                elif description == "schema":
                    self.schema_path.write_bytes(oversized)
                elif description == "registry":
                    self.registry_path.write_bytes(oversized)
                else:
                    self._write_history("record.json", raw=oversized)
                self._assert_cli_rejected(message="maximum JSON input size")

    def test_nesting_limit_applies_to_each_json_input(self):
        depth = validator.MAX_JSON_DEPTH + 1
        nested = ("[" * depth + "0" + "]" * depth).encode("ascii")
        for description in ("candidate", "schema", "registry", "history"):
            with self.subTest(input_type=description):
                self._write_schema()
                self._write_registry()
                for history_file in self.approved_dir.rglob("*.json"):
                    history_file.unlink()
                self._write_candidate()
                if description == "candidate":
                    self._write_candidate(raw=nested)
                elif description == "schema":
                    self.schema_path.write_bytes(nested)
                elif description == "registry":
                    self.registry_path.write_bytes(nested)
                else:
                    self._write_history("record.json", raw=nested)
                self._assert_cli_rejected(message="maximum JSON nesting depth")

    def test_candidate_symlink_is_rejected_where_supported(self):
        target = self.temporary_root / "candidate-target.json"
        target.write_text(json.dumps(self.candidate), encoding="utf-8")
        link = self.temporary_root / "candidate-link.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest("symlink creation is unsupported: {}".format(error))
        self._assert_cli_rejected(link, message="must not be a symbolic link")

    def test_non_regular_candidate_is_rejected(self):
        candidate_dir = self.temporary_root / "candidate-directory"
        candidate_dir.mkdir()
        self._assert_cli_rejected(candidate_dir, message="must be a regular file")

    def test_missing_approved_history_directory_fails_closed(self):
        self.approved_dir.rmdir()
        self._write_candidate()
        self._assert_cli_rejected(message="approved-history directory is missing")

    def test_malformed_approved_history_record_is_rejected(self):
        self._write_candidate()
        self._write_history("broken.json", raw="{")
        self._assert_cli_rejected(message="approved-history record")

    def test_invalid_approved_history_record_identifiers_are_rejected(self):
        invalid_records = (
            ({"update_id": "previous-update"}, "project_id"),
            ({"project_id": "companyhub"}, "update_id"),
            ({"project_id": " ", "update_id": "previous-update"}, "project_id"),
            ({"project_id": "companyhub", "update_id": ""}, "update_id"),
            ({"project_id": 7, "update_id": "previous-update"}, "project_id"),
            ({"project_id": "companyhub", "update_id": ["bad"]}, "update_id"),
            ([{"project_id": "companyhub", "update_id": "nested"}], "top-level JSON object"),
        )
        for record, expected_error in invalid_records:
            with self.subTest(record=record):
                for history_file in self.approved_dir.rglob("*.json"):
                    history_file.unlink()
                self._write_candidate()
                self._write_history("invalid.json", record)
                self._assert_cli_rejected(message=expected_error)

    def test_history_record_allows_unrelated_top_level_metadata(self):
        self._write_candidate()
        self._write_history(
            "record.json",
            {"project_id": "companyhub", "update_id": "old", "note": "legacy"},
        )
        code, _, stderr = self._run_cli()
        self.assertEqual(code, 0, stderr)

    def test_duplicate_approved_pair_is_rejected(self):
        self._write_candidate(dict(self.candidate, update_id="different-update"))
        record = {"project_id": "companyhub", "update_id": "previous-update"}
        self._write_history("first.json", record)
        self._write_history("second.json", record)
        self._assert_cli_rejected(message="approved-history repeats update pair")

    def test_candidate_reusing_approved_pair_is_rejected(self):
        self._write_candidate()
        self._write_history(
            "approved.json",
            {
                "project_id": self.candidate["project_id"],
                "update_id": self.candidate["update_id"],
            },
        )
        self._assert_cli_rejected(message="candidate update pair already exists")

    def test_nested_history_record_is_rejected(self):
        self._write_candidate()
        self._write_history(
            "nested.json",
            {
                "project_id": "companyhub",
                "update_id": "previous-update",
                "metadata": {"project_id": "companyhub", "update_id": "nested"},
            },
        )
        self._assert_cli_rejected(message="contains a nested update record")

    def test_history_symlink_record_is_rejected_where_supported(self):
        self._write_candidate()
        target = self.temporary_root / "history-target.json"
        target.write_text(
            json.dumps({"project_id": "companyhub", "update_id": "old"}),
            encoding="utf-8",
        )
        link = self.approved_dir / "linked.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest("symlink creation is unsupported: {}".format(error))
        self._assert_cli_rejected(message="symbolic-link record")

    def test_history_symlink_directory_is_rejected_where_supported(self):
        self._write_candidate()
        target = self.temporary_root / "history-target"
        target.mkdir()
        link = self.approved_dir / "linked-history"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest("directory symlink creation is unsupported: {}".format(error))
        self._assert_cli_rejected(message="symbolic-link directory")

    def test_duplicate_registry_repository_ownership_is_rejected_case_insensitively(self):
        self.registry["projects"]["backend-engineering-learning-journey"][
            "repository"
        ] = "markkipkoech/companyhub"
        self._write_registry()
        self._write_candidate()
        self._assert_cli_rejected(message="claim the same repository")

    def test_duplicate_registry_destinations_are_rejected(self):
        self.registry["projects"]["companyhub"]["destinations"] = [
            "projects",
            "projects",
        ]
        self._write_registry()
        self._write_candidate()
        self._assert_cli_rejected(message="destinations must be unique")

    def test_unsupported_registry_fields_and_version_are_rejected(self):
        invalid_registries = []
        extra_top_level = json.loads(json.dumps(self.registry))
        extra_top_level["unexpected"] = True
        invalid_registries.append(extra_top_level)
        extra_project_field = json.loads(json.dumps(self.registry))
        extra_project_field["projects"]["companyhub"]["unexpected"] = True
        invalid_registries.append(extra_project_field)
        unsupported_version = json.loads(json.dumps(self.registry))
        unsupported_version["schema_version"] = "2.0"
        invalid_registries.append(unsupported_version)

        self._write_candidate()
        for registry in invalid_registries:
            with self.subTest(registry=registry):
                self.registry = registry
                self._write_registry()
                self._assert_cli_rejected(message="registry")
                self.registry = json.loads(
                    (REPOSITORY_ROOT / "portfolio-data" / "projects" / "registry.json")
                    .read_text(encoding="utf-8")
                )

    def test_malformed_repository_identifiers_are_rejected(self):
        for repository in (
            "not-a-repository",
            "owner//repo",
            "owner_name/repo",
            "owner--name/repo",
            "owner/repo.git",
        ):
            with self.subTest(repository=repository):
                self.registry["projects"]["companyhub"]["repository"] = repository
                errors = validator.validate_registry(self.registry)
                self.assertTrue(any("valid owner/repository" in error for error in errors))
                self.registry = json.loads(
                    (REPOSITORY_ROOT / "portfolio-data" / "projects" / "registry.json")
                    .read_text(encoding="utf-8")
                )

    def test_invalid_evidence_urls_are_rejected(self):
        for evidence_url in ("http://example.com/evidence", "https://example.com:invalid/"):
            with self.subTest(evidence_url=evidence_url):
                candidate = dict(self.candidate, evidence=[evidence_url])
                self._write_candidate(candidate)
                self._assert_cli_rejected()

    def test_evidence_urls_with_userinfo_are_rejected(self):
        for evidence_url in (
            "https://username:password@example.com/evidence",
            "https://username@example.com/evidence",
            "https://:password@example.com/evidence",
            "https://@example.com/evidence",
        ):
            with self.subTest(evidence_url=evidence_url):
                self._write_candidate(dict(self.candidate, evidence=[evidence_url]))
                self._assert_cli_rejected(message="without embedded credentials")

    def test_cli_success_and_failure_exit_codes(self):
        self._write_candidate()
        code, _, _ = self._run_cli()
        self.assertEqual(code, 0)

        self._write_candidate(raw="not JSON")
        code, _, stderr = self._run_cli()
        self.assertEqual(code, 1)
        self.assertIn("ERROR:", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_missing_jsonschema_dependency_returns_exit_code_2(self):
        self._write_candidate()
        real_import = builtins.__import__

        def import_without_jsonschema(name, *args, **kwargs):
            if name == "jsonschema" or name.startswith("jsonschema."):
                raise ImportError("simulated missing dependency")
            return real_import(name, *args, **kwargs)

        code, stdout, stderr = self._run_cli(patch_import=import_without_jsonschema)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("required dependency 'jsonschema' is unavailable", stderr)
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
