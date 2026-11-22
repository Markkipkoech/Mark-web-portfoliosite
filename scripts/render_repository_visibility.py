#!/usr/bin/env python3
"""Render trusted repository visibility into the Pages staging directory."""

import argparse
import json
import re
import sys
from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import urlsplit


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPOSITORY_ROOT / "public-project-visibility.json"
PROJECT_IDS = frozenset(
    {"companyhub", "backend-engineering-learning-journey"}
)
PUBLIC_SITE_FILES = frozenset(
    {
        "index.html",
        "projects.html",
        "engineering.html",
        "learning-journal.html",
        "contact.html",
        "style.css",
        "main.js",
        "hero-bg.jpg",
        "profile.jpg",
    }
)
PAGE_MARKERS = {
    "projects.html": PROJECT_IDS,
    "engineering.html": frozenset({"companyhub"}),
}
MARKER_PATTERN = re.compile(
    r"<!-- repository-visibility:([a-z0-9][a-z0-9-]*) -->"
)
COMMENT_PATTERN = re.compile(r"<!--.*?(?:-->|$)", re.DOTALL)
REPOSITORY_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
GITHUB_OWNER_PATTERN = re.compile(
    r"(?!.*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
)
MARKER_LIKE_PATTERN = re.compile(r"repository[\s_-]*visibility", re.IGNORECASE)


class ConfigurationError(ValueError):
    """An invalid public presentation configuration or staging directory."""


def _unique_object(pairs: Iterable[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(
                "configuration contains a duplicate JSON key: {!r}".format(key)
            )
        result[key] = value
    return result


def _valid_repository_url(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.strip() != value:
        return False
    if any(character.isspace() for character in value) or "?" in value or "#" in value:
        return False

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False

    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.netloc.lower() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        return False

    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return False
    if parsed.path.endswith("//"):
        return False
    segments = parsed.path.strip("/").split("/")
    return (
        len(segments) == 2
        and all(
            segment not in ("", ".", "..")
            and REPOSITORY_SEGMENT_PATTERN.fullmatch(segment)
            for segment in segments
        )
        and len(segments[0]) <= 39
        and GITHUB_OWNER_PATTERN.fullmatch(segments[0])
        and not segments[1].lower().endswith(".git")
    )


def validate_project_entry(entry: Any) -> Dict[str, str]:
    if not isinstance(entry, dict):
        raise ConfigurationError("each project entry must be a JSON object")

    project_id = entry.get("project_id")
    if not isinstance(project_id, str) or project_id not in PROJECT_IDS:
        raise ConfigurationError("project_id must match an existing project")

    visibility = entry.get("repository_visibility")
    if visibility not in ("public", "private", "unavailable"):
        raise ConfigurationError(
            "project {!r} repository_visibility must be public, private, "
            "or unavailable".format(project_id)
        )

    required_keys = {"project_id", "repository_visibility"}
    if visibility == "public":
        if set(entry) != required_keys | {"public_repository_url"}:
            raise ConfigurationError(
                "public project {!r} requires only project_id, "
                "repository_visibility, and public_repository_url".format(
                    project_id
                )
            )
        if not _valid_repository_url(entry.get("public_repository_url")):
            raise ConfigurationError(
                "public project {!r} requires a valid HTTPS GitHub repository URL "
                "without credentials".format(project_id)
            )
    elif set(entry) != required_keys:
        if "public_repository_url" in entry:
            raise ConfigurationError(
                "project {!r} must not define a repository URL unless visibility "
                "is public".format(project_id)
            )
        raise ConfigurationError(
            "project {!r} contains unsupported configuration fields".format(
                project_id
            )
        )

    return entry


def load_configuration(path: Path = CONFIG_PATH) -> Dict[str, Dict[str, str]]:
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except FileNotFoundError:
        raise ConfigurationError(
            "public visibility configuration was not found: {}".format(path)
        )
    except IsADirectoryError:
        raise ConfigurationError(
            "public visibility configuration path is a directory: {}".format(path)
        )
    except UnicodeDecodeError:
        raise ConfigurationError(
            "public visibility configuration is not valid UTF-8: {}".format(path)
        )
    except json.JSONDecodeError as error:
        raise ConfigurationError(
            "public visibility configuration contains malformed JSON at line {}, "
            "column {}: {}".format(error.lineno, error.colno, error.msg)
        )
    except OSError as error:
        raise ConfigurationError(
            "cannot read public visibility configuration: {}".format(error)
        )

    if not isinstance(raw, dict) or set(raw) != {"projects"}:
        raise ConfigurationError(
            "public visibility configuration must contain only a projects array"
        )
    if not isinstance(raw["projects"], list):
        raise ConfigurationError("public visibility projects must be an array")

    projects: Dict[str, Dict[str, str]] = {}
    for entry in raw["projects"]:
        project = validate_project_entry(entry)
        project_id = project["project_id"]
        if project_id in projects:
            raise ConfigurationError(
                "public visibility configuration repeats project {!r}".format(
                    project_id
                )
            )
        projects[project_id] = project

    if set(projects) != PROJECT_IDS:
        missing = sorted(PROJECT_IDS - set(projects))
        unknown = sorted(set(projects) - PROJECT_IDS)
        details: List[str] = []
        if missing:
            details.append("missing {}".format(", ".join(missing)))
        if unknown:
            details.append("unknown {}".format(", ".join(unknown)))
        raise ConfigurationError(
            "public visibility configuration must cover all existing projects: "
            + "; ".join(details)
        )

    return projects


def render_visibility(entry: Mapping[str, str]) -> str:
    project = validate_project_entry(dict(entry))
    visibility = project["repository_visibility"]
    if visibility == "unavailable":
        return ""
    if visibility == "private":
        content = '<span class="project-status">Source repository is private</span>'
    else:
        url = escape(project["public_repository_url"], quote=True)
        content = (
            '<a class="project-link" href="{}" target="_blank" '
            'rel="noopener noreferrer">Project repository</a>'.format(url)
        )
    return '<p class="repository-visibility">{}</p>'.format(content)


def _validate_staging_directory(site_dir: Path) -> Path:
    try:
        resolved = site_dir.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError(
            "Pages staging directory cannot be resolved: {}".format(error)
        )
    if not resolved.is_dir():
        raise ConfigurationError("Pages staging path is not a directory")
    try:
        resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        pass
    else:
        raise ConfigurationError(
            "Pages staging directory must be outside the repository"
        )

    entries = list(resolved.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise ConfigurationError(
            "Pages staging directory may contain only regular allowlisted files"
        )
    actual_files = {entry.name for entry in entries}
    if actual_files != PUBLIC_SITE_FILES:
        missing = sorted(PUBLIC_SITE_FILES - actual_files)
        unexpected = sorted(actual_files - PUBLIC_SITE_FILES)
        details = []
        if missing:
            details.append("missing {}".format(", ".join(missing)))
        if unexpected:
            details.append("unexpected {}".format(", ".join(unexpected)))
        raise ConfigurationError(
            "Pages staging contents do not match the public allowlist: "
            + "; ".join(details)
        )
    return resolved


def _render_page(
    path: Path,
    projects: Mapping[str, Dict[str, str]],
    expected_markers: Iterable[str],
) -> str:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigurationError(
            "cannot read staged page {}: {}".format(path.name, error)
        )

    marker_ids = []
    for comment_match in COMMENT_PATTERN.finditer(content):
        comment = comment_match.group(0)
        if MARKER_LIKE_PATTERN.search(comment) is None:
            continue
        marker_match = MARKER_PATTERN.fullmatch(comment)
        if marker_match is None:
            raise ConfigurationError(
                "staged page {} contains a malformed repository-visibility marker"
                .format(path.name)
            )
        marker_ids.append(marker_match.group(1))

    expected = set(expected_markers)
    actual = set(marker_ids)
    duplicates = sorted(
        project_id
        for project_id in actual
        if marker_ids.count(project_id) > 1
    )
    unknown = sorted(actual - projects.keys())
    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    if duplicates or unknown or unexpected or missing:
        problems = []
        if duplicates:
            problems.append("duplicate {}".format(", ".join(duplicates)))
        if unknown:
            problems.append("unknown {}".format(", ".join(unknown)))
        if unexpected:
            problems.append("unexpected {}".format(", ".join(unexpected)))
        if missing:
            problems.append("missing {}".format(", ".join(missing)))
        raise ConfigurationError(
            "staged page {} has invalid repository-visibility markers: {}"
            .format(path.name, "; ".join(problems))
        )

    def replace_marker(match: re.Match) -> str:
        project_id = match.group(1)
        if project_id not in projects:
            raise ConfigurationError(
                "staged page {} references an unconfigured project".format(
                    path.name
                )
            )
        return render_visibility(projects[project_id])

    rendered = MARKER_PATTERN.sub(replace_marker, content)
    return rendered


def render_staged_site(site_dir: Path, config_path: Path = CONFIG_PATH) -> None:
    staging_directory = _validate_staging_directory(site_dir)
    projects = load_configuration(config_path)
    rendered_pages = []
    for page_name, expected_markers in PAGE_MARKERS.items():
        page_path = staging_directory / page_name
        rendered_content = _render_page(page_path, projects, expected_markers)
        rendered_pages.append((page_path, rendered_content))

    for page_path, rendered_content in rendered_pages:
        try:
            page_path.write_text(rendered_content, encoding="utf-8")
        except OSError as error:
            raise ConfigurationError(
                "cannot write rendered staged page {}: {}".format(
                    page_path.name, error
                )
            )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render public repository visibility in the Pages staging directory."
    )
    parser.add_argument("site_dir", type=Path, help="existing Pages staging directory")
    args = parser.parse_args(argv)
    try:
        render_staged_site(args.site_dir)
    except ConfigurationError as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1
    print("Repository visibility rendered in the allowlisted Pages staging directory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
