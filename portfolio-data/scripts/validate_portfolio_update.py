#!/usr/bin/env python3
"""Validate one candidate portfolio update without changing portfolio data."""

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit


class ValidationFailure(Exception):
    """A validation or configuration problem safe to show to the user."""


class ValidationConfigurationFailure(ValidationFailure):
    """The schema, registry, or validator environment cannot be used safely."""


MAX_JSON_BYTES = 1_048_576  # 1 MiB maximum for schema, registry, candidate, and history JSON.
MAX_JSON_DEPTH = 100
ALLOWED_DESTINATIONS = frozenset(
    {"projects", "engineering", "learning-journal"}
)
OWNER_PATTERN = re.compile(
    r"(?!.*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
)
REPOSITORY_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}")


class DuplicateJSONKeyError(ValueError):
    """A JSON object contains a key more than once."""


class NonStandardJSONConstantError(ValueError):
    """JSON contains a non-standard numeric constant."""


def reject_nonstandard_json_constant(value: str) -> Any:
    raise NonStandardJSONConstantError(
        "non-standard JSON constant {!r} is not permitted".format(value)
    )


def unique_json_object(pairs: Iterable[Any]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(
                "duplicate JSON object key {!r}; object keys must be unique".format(
                    key
                )
            )
        result[key] = value
    return result


def check_json_nesting_depth(text: str, description: str, path: Path) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValidationFailure(
                    "{} ({}) exceeds the maximum JSON nesting depth of {}".format(
                        description, path, MAX_JSON_DEPTH
                    )
                )
        elif character in "]}" and depth:
            depth -= 1


def read_json(path: Path, description: str) -> Any:
    descriptor = None
    try:
        initial_stat = path.lstat()
        if stat.S_ISLNK(initial_stat.st_mode):
            raise ValidationFailure(
                "{} must not be a symbolic link: {}".format(description, path)
            )
        if not stat.S_ISREG(initial_stat.st_mode):
            raise ValidationFailure(
                "{} must be a regular file: {}".format(description, path)
            )
        if initial_stat.st_size > MAX_JSON_BYTES:
            raise ValidationFailure(
                "{} exceeds the maximum JSON input size of {} bytes: {}".format(
                    description, MAX_JSON_BYTES, path
                )
            )

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags)
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ValidationFailure(
                "{} must be a regular file: {}".format(description, path)
            )
        if opened_stat.st_size > MAX_JSON_BYTES:
            raise ValidationFailure(
                "{} exceeds the maximum JSON input size of {} bytes: {}".format(
                    description, MAX_JSON_BYTES, path
                )
            )
        current_stat = path.lstat()
        if stat.S_ISLNK(current_stat.st_mode):
            raise ValidationFailure(
                "{} must not be a symbolic link: {}".format(description, path)
            )
        if (initial_stat.st_dev, initial_stat.st_ino) != (
            opened_stat.st_dev,
            opened_stat.st_ino,
        ):
            raise ValidationFailure(
                "{} changed while it was being opened: {}".format(description, path)
            )

        binary_file = os.fdopen(descriptor, "rb")
        descriptor = None
        with binary_file:
            raw = binary_file.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise ValidationFailure(
                "{} exceeds the maximum JSON input size of {} bytes: {}".format(
                    description, MAX_JSON_BYTES, path
                )
            )
        text = raw.decode("utf-8")
        check_json_nesting_depth(text, description, path)
        return json.loads(
            text,
            object_pairs_hook=unique_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except FileNotFoundError:
        raise ValidationFailure("{} file not found: {}".format(description, path))
    except IsADirectoryError:
        raise ValidationFailure("{} path is a directory: {}".format(description, path))
    except DuplicateJSONKeyError as error:
        raise ValidationFailure(
            "{} ({}) contains {}".format(description, path, error)
        )
    except NonStandardJSONConstantError as error:
        raise ValidationFailure(
            "{} ({}) contains invalid JSON: {}".format(description, path, error)
        )
    except UnicodeDecodeError as error:
        raise ValidationFailure(
            "{} ({}) is not valid UTF-8 (byte {})".format(
                description, path, error.start
            )
        )
    except json.JSONDecodeError as error:
        raise ValidationFailure(
            "{} ({}) contains malformed JSON at line {}, column {}: {}".format(
                description, path, error.lineno, error.colno, error.msg
            )
        )
    except ValidationFailure:
        raise
    except RecursionError:
        raise ValidationFailure(
            "{} ({}) exceeds the supported JSON nesting depth".format(
                description, path
            )
        )
    except (OSError, ValueError) as error:
        raise ValidationFailure(
            "cannot read {} ({}): {}".format(
                description, path, getattr(error, "strerror", None) or str(error)
            )
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)


def json_path(parts: Iterable[Any]) -> str:
    result = "$"
    for part in parts:
        if isinstance(part, int):
            result += "[{}]".format(part)
        else:
            result += "[{}]".format(json.dumps(str(part), ensure_ascii=True))
    if len(result) > 180:
        return result[:177] + "..."
    return result


def validate_registry(registry: Any) -> List[str]:
    errors = []
    if not isinstance(registry, dict):
        return ["registry must be a JSON object"]

    expected_fields = {"schema_version", "projects"}
    if set(registry) != expected_fields:
        errors.append(
            "registry must contain exactly schema_version and projects fields"
        )
    version = registry.get("schema_version")
    if version != "1.0":
        errors.append("registry schema_version must be the supported version '1.0'")

    projects = registry.get("projects")
    if not isinstance(projects, dict):
        errors.append("registry projects must be a JSON object")
        return errors
    if not projects:
        errors.append("registry projects must not be empty")

    repository_owners = {}
    entry_fields = {"repository", "display_name", "enabled", "destinations"}
    for project_id, project in projects.items():
        if not isinstance(project_id, str) or not project_id.strip():
            errors.append("registry contains an empty or invalid project key")
            continue
        if not isinstance(project, dict):
            errors.append(
                "registry project {!r} must be a JSON object".format(project_id)
            )
            continue
        if set(project) != entry_fields:
            errors.append(
                "registry project {!r} must contain exactly repository, "
                "display_name, enabled, and destinations fields".format(project_id)
            )

        repository = project.get("repository")
        if not isinstance(repository, str) or not repository.strip():
            errors.append(
                "registry project {!r} requires a non-empty repository".format(
                    project_id
                )
            )
        elif not valid_repository_identifier(repository):
            errors.append(
                "registry project {!r} repository must be a valid owner/repository "
                "identifier".format(project_id)
            )
        else:
            normalized_repository = repository.casefold()
            if normalized_repository in repository_owners:
                errors.append(
                    "registry projects {!r} and {!r} claim the same repository"
                    .format(repository_owners[normalized_repository], project_id)
                )
            else:
                repository_owners[normalized_repository] = project_id

        display_name = project.get("display_name")
        if not isinstance(display_name, str) or not display_name.strip():
            errors.append(
                "registry project {!r} requires a non-empty display_name".format(
                    project_id
                )
            )
        if not isinstance(project.get("enabled"), bool):
            errors.append(
                "registry project {!r} enabled must be a boolean".format(project_id)
            )
        destinations = project.get("destinations")
        if not isinstance(destinations, list) or not destinations:
            errors.append(
                "registry project {!r} destinations must be a list of "
                "non-empty permitted destinations".format(project_id)
            )
            continue
        if any(not isinstance(destination, str) for destination in destinations):
            errors.append(
                "registry project {!r} destinations must contain only strings"
                .format(project_id)
            )
            continue
        if len(set(destinations)) != len(destinations):
            errors.append(
                "registry project {!r} destinations must be unique".format(project_id)
            )
        invalid_destinations = sorted(
            set(destinations) - ALLOWED_DESTINATIONS
        )
        if invalid_destinations:
            errors.append(
                "registry project {!r} contains unsupported destinations: {}".format(
                    project_id, ", ".join(invalid_destinations)
                )
            )
    return errors


def validate_pipeline_registry(registry: Any) -> dict:
    """Validate trusted repository IDs, then return the local-validator view.

    ``repository_id`` is pipeline provenance metadata, not part of the current
    local registry contract. This additive helper removes it only from the
    in-memory candidate-validation view while checking its type and uniqueness.
    """
    if not isinstance(registry, dict):
        raise ValidationConfigurationFailure("registry configuration is invalid")
    projects = registry.get("projects")
    if not isinstance(projects, dict):
        raise ValidationConfigurationFailure("registry configuration is invalid")

    seen_repository_ids = {}
    validation_projects = {}
    for project_id, project in projects.items():
        if not isinstance(project, dict):
            validation_projects[project_id] = project
            continue
        candidate_project = dict(project)
        if "repository_id" in candidate_project:
            repository_id = candidate_project.pop("repository_id")
            if type(repository_id) is not int or repository_id <= 0:
                raise ValidationConfigurationFailure(
                    "registry repository ID configuration is invalid"
                )
            if repository_id in seen_repository_ids:
                raise ValidationConfigurationFailure(
                    "registry repository IDs are not unique"
                )
            seen_repository_ids[repository_id] = project_id
        validation_projects[project_id] = candidate_project

    validation_registry = dict(registry)
    validation_registry["projects"] = validation_projects
    if validate_registry(validation_registry):
        raise ValidationConfigurationFailure("registry configuration is invalid")
    return validation_registry


def valid_repository_identifier(value: str) -> bool:
    if value.count("/") != 1:
        return False
    owner, repository = value.split("/")
    return bool(
        OWNER_PATTERN.fullmatch(owner)
        and REPOSITORY_NAME_PATTERN.fullmatch(repository)
        and repository not in (".", "..")
        and not repository.startswith(".")
        and not repository.endswith(".")
        and not repository.lower().endswith(".git")
    )


def validate_schema_configuration(
    schema: Any, validator_class: Any, schema_error_type: Any
) -> Optional[str]:
    if not isinstance(schema, dict):
        return "schema must be a JSON object"

    expected_dialect = "https://json-schema.org/draft/2020-12/schema"
    if schema.get("$schema") != expected_dialect:
        return "schema must declare the Draft 2020-12 dialect ({})".format(
            expected_dialect
        )
    try:
        validator_class.check_schema(schema)
    except schema_error_type as error:
        schema_path = json_path(getattr(error, "absolute_path", []))
        keyword = getattr(error, "validator", None)
        detail = " at {}".format(schema_path)
        if keyword:
            detail += " ({})".format(keyword)
        return "schema configuration is invalid{}".format(detail)
    return None


def add_whitespace_errors(value: Any, path: Tuple[Any, ...], errors: List[str]) -> None:
    pending = [(value, path)]
    while pending:
        current, current_path = pending.pop()
        if isinstance(current, str):
            if not current.strip():
                errors.append(
                    "{} must not contain a whitespace-only text value".format(
                        json_path(current_path)
                    )
                )
        elif isinstance(current, list):
            pending.extend(
                (item, current_path + (index,))
                for index, item in reversed(list(enumerate(current)))
            )
        elif isinstance(current, dict):
            pending.extend(
                (item, current_path + (key,))
                for key, item in reversed(list(current.items()))
            )


def schema_error_message(error: Any) -> str:
    path = json_path(error.absolute_path)
    validator = error.validator
    details = {
        "additionalProperties": "contains a property not allowed by the schema",
        "format": "must satisfy the schema's {} format".format(
            error.validator_value
        ),
        "maxItems": "contains too many items",
        "maxLength": "is longer than allowed",
        "minItems": "contains too few items",
        "minLength": "is shorter than allowed",
        "pattern": "does not match the required pattern",
        "required": "is missing a required property",
        "type": "does not have the required type",
        "enum": "is not one of the allowed values",
        "const": "does not match the required constant",
        "uniqueItems": "contains duplicate items",
    }
    if validator == "required" and isinstance(error.instance, dict):
        missing = [
            property_name
            for property_name in error.validator_value
            if property_name not in error.instance
        ]
        if missing:
            return "{} is missing required property {}".format(
                path, ", ".join(repr(name) for name in missing)
            )
    return "{} {}".format(
        path, details.get(validator, "fails the schema's {} rule".format(validator))
    )


def add_registry_errors(candidate: Any, registry: Any, errors: List[str]) -> None:
    if not isinstance(candidate, dict) or not isinstance(registry, dict):
        return
    projects = registry.get("projects")
    if not isinstance(projects, dict):
        return

    project_id = candidate.get("project_id")
    if not isinstance(project_id, str):
        return
    project = projects.get(project_id)
    if project is None:
        errors.append("$.project_id does not exactly match a registry project key")
        return
    if not isinstance(project, dict):
        return
    if project.get("enabled") is not True:
        errors.append("the registry project selected by $.project_id is disabled")
    destinations = project.get("destinations")
    destination = candidate.get("destination")
    if (
        isinstance(destination, str)
        and isinstance(destinations, list)
        and destination not in destinations
    ):
        errors.append("$.destination is not permitted for the selected project")


def add_https_errors(candidate: Any, errors: List[str]) -> None:
    if not isinstance(candidate, dict):
        return
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list):
        return
    for index, evidence_url in enumerate(evidence):
        if not isinstance(evidence_url, str):
            continue
        try:
            parsed_url = urlsplit(evidence_url)
            valid_url = (
                parsed_url.scheme.lower() == "https"
                and bool(parsed_url.hostname)
                and "@" not in parsed_url.netloc
            )
            parsed_url.port
        except ValueError:
            valid_url = False
        if not valid_url:
            errors.append(
                "$.evidence[{}] must be a valid HTTPS URL with a hostname and port, "
                "without embedded credentials".format(index)
            )


def _validate_candidate_value(
    candidate: Any,
    schema: Any,
    registry: Any,
    validator_class: Any,
    format_checker: Any,
) -> List[str]:
    """Apply shared in-memory schema and semantic checks, excluding history."""
    errors = []
    pending = [(candidate, 0)]
    while pending:
        value, parent_depth = pending.pop()
        if isinstance(value, (dict, list)):
            depth = parent_depth + 1
            if depth > MAX_JSON_DEPTH:
                return [
                    "candidate structure exceeds the validator's supported nesting depth"
                ]
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth) for child in children)
    validator = validator_class(schema, format_checker=format_checker)
    try:
        schema_errors = sorted(
            validator.iter_errors(candidate),
            key=lambda error: (
                json_path(error.absolute_path),
                str(error.validator),
            ),
        )
    except RecursionError:
        return ["candidate structure exceeds the validator's supported nesting depth"]
    errors.extend(schema_error_message(error) for error in schema_errors)
    add_whitespace_errors(candidate, (), errors)
    add_registry_errors(candidate, registry, errors)
    add_https_errors(candidate, errors)
    return errors


def validate_candidate_data(
    candidate: Any,
    schema: Any,
    registry: Any,
    *,
    validator_class: Any = None,
    format_checker: Any = None,
    schema_error_type: Any = None,
) -> List[str]:
    """Validate already-parsed candidate data without reading files or history.

    This API shares the local validator's schema and semantic checks. It leaves
    approved-history duplicate handling to the caller, which has the pipeline's
    revision context. Returned diagnostics contain paths/rules, never values.
    """
    if (
        validator_class is None
        or format_checker is None
        or schema_error_type is None
    ):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
            from jsonschema.exceptions import SchemaError
        except ImportError as error:
            raise ValidationConfigurationFailure(
                "required dependency 'jsonschema' is unavailable"
            ) from error
        validator_class = validator_class or Draft202012Validator
        format_checker = format_checker or FormatChecker()
        schema_error_type = schema_error_type or SchemaError
    schema_error = validate_schema_configuration(
        schema, validator_class, schema_error_type
    )
    if schema_error:
        raise ValidationConfigurationFailure(schema_error)
    validation_registry = validate_pipeline_registry(registry)
    return _validate_candidate_value(
        candidate, schema, validation_registry, validator_class, format_checker
    )


def collect_history_records(
    value: Any, path: Tuple[Any, ...], file_path: Path, errors: List[str]
) -> List[Tuple[str, str]]:
    record_path = "{}:{}".format(file_path, json_path(path))
    if not isinstance(value, dict):
        errors.append(
            "{} must contain one top-level JSON object".format(record_path)
        )
        return []

    project_id = value.get("project_id")
    update_id = value.get("update_id")
    if not isinstance(project_id, str) or not project_id.strip():
        errors.append(
            "{} must contain a non-empty string project_id".format(record_path)
        )
    if not isinstance(update_id, str) or not update_id.strip():
        errors.append(
            "{} must contain a non-empty string update_id".format(record_path)
        )

    pending = []
    for key, child in value.items():
        if isinstance(child, (dict, list)):
            pending.append((child, path + (key,)))
    has_nested_record = False
    while pending:
        current, current_path = pending.pop()
        if isinstance(current, dict):
            if "project_id" in current or "update_id" in current:
                errors.append(
                    "{} contains a nested update record; identifiers must be at the top level".format(
                        "{}:{}".format(file_path, json_path(current_path))
                    )
                )
                has_nested_record = True
            for key, child in current.items():
                if isinstance(child, (dict, list)):
                    pending.append((child, current_path + (key,)))
        elif isinstance(current, list):
            for index, child in enumerate(current):
                if isinstance(child, (dict, list)):
                    pending.append((child, current_path + (index,)))

    if (
        isinstance(project_id, str)
        and project_id.strip()
        and isinstance(update_id, str)
        and update_id.strip()
        and not has_nested_record
    ):
        return [(project_id, update_id)]
    return []


def raise_walk_error(error: OSError) -> None:
    raise error


def load_approved_pairs(root: Path, errors: List[str]) -> Set[Tuple[str, str]]:
    approved_dir = root / "portfolio-data" / "updates" / "approved"
    try:
        approved_stat = approved_dir.lstat()
    except FileNotFoundError:
        errors.append(
            "approved-history directory is missing: {}".format(approved_dir)
        )
        return set()
    except OSError as error:
        errors.append(
            "cannot inspect approved-history path {}: {}".format(
                approved_dir, error.strerror or str(error)
            )
        )
        return set()
    if stat.S_ISLNK(approved_stat.st_mode):
        errors.append(
            "approved-history path must not be a symbolic link: {}".format(
                approved_dir
            )
        )
        return set()
    if not stat.S_ISDIR(approved_stat.st_mode):
        errors.append(
            "approved-history path is not a directory: {}".format(approved_dir)
        )
        return set()

    pairs = set()
    record_files = []
    try:
        for current_dir, directories, filenames in os.walk(
            approved_dir, onerror=raise_walk_error
        ):
            current_path = Path(current_dir)
            for directory in list(directories):
                directory_path = current_path / directory
                try:
                    directory_mode = directory_path.lstat().st_mode
                except OSError as error:
                    errors.append(
                        "cannot inspect approved-history entry {}: {}".format(
                            directory_path, error.strerror or str(error)
                        )
                    )
                    directories.remove(directory)
                    continue
                if stat.S_ISLNK(directory_mode):
                    errors.append(
                        "approved-history contains a symbolic-link directory: {}".format(
                            directory_path
                        )
                    )
                    directories.remove(directory)
                elif directory_path.suffix.lower() == ".json":
                    errors.append(
                        "approved-history .json entry is not a regular file: {}".format(
                            directory_path
                        )
                    )
                    directories.remove(directory)
            for filename in filenames:
                record_file = current_path / filename
                if record_file.suffix.lower() != ".json":
                    continue
                try:
                    record_mode = record_file.lstat().st_mode
                except OSError as error:
                    errors.append(
                        "cannot inspect approved-history entry {}: {}".format(
                            record_file, error.strerror or str(error)
                        )
                    )
                    continue
                if stat.S_ISLNK(record_mode):
                    errors.append(
                        "approved-history contains a symbolic-link record: {}".format(
                            record_file
                        )
                    )
                elif stat.S_ISREG(record_mode):
                    record_files.append(record_file)
                else:
                    errors.append(
                        "approved-history .json entry is not a regular file: {}".format(
                            record_file
                        )
                    )
    except OSError as error:
        errors.append(
            "cannot scan approved-history directory {}: {}".format(
                approved_dir, error.strerror or str(error)
            )
        )
        return pairs

    for record_file in sorted(record_files):
        try:
            record_data = read_json(record_file, "approved-history record")
        except ValidationFailure as error:
            errors.append(str(error))
            continue
        record_errors = []
        found = collect_history_records(record_data, (), record_file, record_errors)
        errors.extend(record_errors)
        for pair in found:
            if pair in pairs:
                errors.append(
                    "approved-history repeats update pair {!r}/{!r}".format(*pair)
                )
            else:
                pairs.add(pair)
    return pairs


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate one candidate portfolio update JSON file."
    )
    parser.add_argument("candidate", help="path to the candidate JSON file")
    args = parser.parse_args(argv)

    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except ImportError:
        print(
            "ERROR: required dependency 'jsonschema' is unavailable; "
            "install it in the validation environment to use this command.",
            file=sys.stderr,
        )
        return 2

    repository_root = Path(__file__).resolve().parents[2]
    data_root = repository_root / "portfolio-data"

    try:
        schema = read_json(
            data_root / "schemas" / "portfolio-update.schema.json",
            "portfolio update schema",
        )
        schema_error = validate_schema_configuration(
            schema, Draft202012Validator, SchemaError
        )
        if schema_error:
            raise ValidationFailure(schema_error)

        registry = read_json(
            data_root / "projects" / "registry.json", "project registry"
        )
        registry_errors = validate_registry(registry)
        if registry_errors:
            raise ValidationFailure("; ".join(registry_errors))

        candidate = read_json(Path(args.candidate), "candidate JSON")
    except ValidationFailure as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1

    errors = _validate_candidate_value(
        candidate, schema, registry, Draft202012Validator, FormatChecker()
    )

    approved_pairs = load_approved_pairs(repository_root, errors)
    if isinstance(candidate, dict):
        project_id = candidate.get("project_id")
        update_id = candidate.get("update_id")
        if (
            isinstance(project_id, str)
            and isinstance(update_id, str)
            and (project_id, update_id) in approved_pairs
        ):
            errors.append("candidate update pair already exists in approved history")

    if errors:
        for error in errors:
            print("ERROR: {}".format(error), file=sys.stderr)
        return 1

    print(
        "Validation succeeded; the candidate may proceed to human review, "
        "but is not approved for publication."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
