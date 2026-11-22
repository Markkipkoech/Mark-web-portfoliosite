import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import render_repository_visibility as renderer


def public_entry(project_id="backend-engineering-learning-journey", url=None):
    entry = {
        "project_id": project_id,
        "repository_visibility": "public",
    }
    if url is not None:
        entry["public_repository_url"] = url
    return entry


class RepositoryVisibilityTests(unittest.TestCase):
    def test_all_visibility_states_render_according_to_policy(self):
        public = public_entry(url="https://github.com/example/project")
        private = {
            "project_id": "companyhub",
            "repository_visibility": "private",
        }
        unavailable = {
            "project_id": "companyhub",
            "repository_visibility": "unavailable",
        }

        public_html = renderer.render_visibility(public)
        private_html = renderer.render_visibility(private)
        unavailable_html = renderer.render_visibility(unavailable)

        self.assertIn('href="https://github.com/example/project"', public_html)
        self.assertIn("Project repository", public_html)
        self.assertIn("Source repository is private", private_html)
        self.assertNotIn("<a ", private_html)
        self.assertEqual(unavailable_html, "")

    def test_public_visibility_requires_a_valid_repository_url(self):
        with self.assertRaises(renderer.ConfigurationError):
            renderer.validate_project_entry(public_entry())

        valid_urls = (
            "https://github.com/example/project",
            "https://github.com/Mark-Kipkoech/backend_engineering.learning",
            "https://github.com/example/project/",
        )
        for url in valid_urls:
            with self.subTest(valid_url=url):
                renderer.validate_project_entry(public_entry(url=url))

        invalid_urls = (
            "not-a-url",
            "http://github.com/owner/repo",
            "https://example.com/owner/repo",
            "https://github.com/owner",
            "https://github.com/owner/repo/issues",
            "https://github.com//owner/repo",
            "https://github.com:/owner/repo",
            "https://github.com/owner/repo//",
            "https://user:password@github.com/owner/repo",
            "https://github.com:443/owner/repo",
            "https://github.com/owner/repo?tab=readme",
            "https://github.com/owner/repo#readme",
            "https://github.com/owner_name/repo",
            "https://github.com/owner--name/repo",
            "https://github.com/-owner/repo",
            "https://github.com/owner-/repo",
            "https://github.com/this-owner-name-is-longer-than-thirty-nine-characters/repo",
            "https://github.com/owner/repo%2Fother",
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(renderer.ConfigurationError):
                    renderer.validate_project_entry(public_entry(url=url))

    def test_repository_url_attribute_is_html_escaped(self):
        unsafe_url = 'https://github.com/example/repo" data-note="a&b'
        entry = {
            "project_id": "backend-engineering-learning-journey",
            "repository_visibility": "public",
            "public_repository_url": unsafe_url,
        }
        with patch.object(renderer, "validate_project_entry", return_value=entry):
            output = renderer.render_visibility(entry)

        self.assertIn(
            'href="https://github.com/example/repo&quot; data-note=&quot;a&amp;b"',
            output,
        )
        self.assertNotIn('href="' + unsafe_url + '"', output)

    def test_private_and_unavailable_states_prohibit_repository_urls(self):
        for visibility in ("private", "unavailable"):
            with self.subTest(visibility=visibility):
                with self.assertRaises(renderer.ConfigurationError):
                    renderer.validate_project_entry(
                        {
                            "project_id": "companyhub",
                            "repository_visibility": visibility,
                            "public_repository_url": "https://github.com/owner/repo",
                        }
                    )

    def test_unknown_visibility_and_project_ids_are_rejected(self):
        with self.assertRaises(renderer.ConfigurationError):
            renderer.validate_project_entry(
                {
                    "project_id": "companyhub",
                    "repository_visibility": "unknown",
                }
            )
        with self.assertRaises(renderer.ConfigurationError):
            renderer.validate_project_entry(
                {
                    "project_id": "unregistered-project",
                    "repository_visibility": "unavailable",
                }
            )

    def test_malformed_configuration_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "visibility.json"
            config_path.write_text("{", encoding="utf-8")

            with self.assertRaisesRegex(
                renderer.ConfigurationError, "malformed JSON"
            ):
                renderer.load_configuration(config_path)

    def test_duplicate_and_missing_project_entries_are_rejected(self):
        companyhub = {
            "project_id": "companyhub",
            "repository_visibility": "private",
        }
        duplicate_entries = {
            "projects": [
                companyhub,
                companyhub,
                {
                    "project_id": "backend-engineering-learning-journey",
                    "repository_visibility": "unavailable",
                },
            ]
        }
        missing_entry = {"projects": [companyhub]}

        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "visibility.json"
            for value, message in (
                (duplicate_entries, "repeats project"),
                (missing_entry, "must cover all existing projects"),
            ):
                with self.subTest(message=message):
                    config_path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(
                        renderer.ConfigurationError, message
                    ):
                        renderer.load_configuration(config_path)

    def test_candidate_schema_rejects_visibility_authority_fields(self):
        schema_path = (
            REPOSITORY_ROOT
            / "portfolio-data"
            / "schemas"
            / "portfolio-update.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        candidate = {
            "schema_version": "1.0",
            "project_id": "companyhub",
            "update_id": "sales-integrity",
            "date": "2026-11-10",
            "category": "engineering",
            "title": "Database safeguards",
            "summary": "A concise factual milestone summary.",
            "highlights": ["Added data integrity safeguards."],
            "technologies": ["Python"],
            "evidence": ["https://example.com/evidence"],
            "destination": "projects",
        }
        self.assertEqual(list(validator.iter_errors(candidate)), [])

        for field, value in (
            ("repository_visibility", "public"),
            ("repository_url", "https://github.com/owner/repo"),
            ("public_repository_url", "https://github.com/owner/repo"),
        ):
            with self.subTest(field=field):
                unauthorized = dict(candidate)
                unauthorized[field] = value
                errors = list(validator.iter_errors(unauthorized))
                self.assertTrue(
                    any(error.validator == "additionalProperties" for error in errors)
                )

    def test_staged_site_renders_all_views_and_enforces_exact_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            site_dir = temporary_root / "site"
            site_dir.mkdir()
            for file_name in renderer.PUBLIC_SITE_FILES:
                (site_dir / file_name).write_text("", encoding="utf-8")

            projects_page = (
                "<!-- repository-visibility:companyhub -->\n"
                "<!-- repository-visibility:backend-engineering-learning-journey -->"
            )
            (site_dir / "projects.html").write_text(
                projects_page, encoding="utf-8"
            )
            (site_dir / "engineering.html").write_text(
                "<!-- repository-visibility:companyhub -->", encoding="utf-8"
            )

            config_path = temporary_root / "visibility.json"
            config_path.write_text(
                json.dumps(
                    {
                        "projects": [
                            {
                                "project_id": "companyhub",
                                "repository_visibility": "private",
                            },
                            public_entry(url="https://github.com/example/project"),
                        ]
                    }
                ),
                encoding="utf-8",
            )

            renderer.render_staged_site(site_dir, config_path)

            projects_output = (site_dir / "projects.html").read_text(
                encoding="utf-8"
            )
            engineering_output = (site_dir / "engineering.html").read_text(
                encoding="utf-8"
            )
            self.assertIn("Source repository is private", projects_output)
            self.assertIn('href="https://github.com/example/project"', projects_output)
            self.assertIn("Source repository is private", engineering_output)
            self.assertNotIn("repository-visibility:", projects_output)
            self.assertEqual(
                {entry.name for entry in site_dir.iterdir()},
                renderer.PUBLIC_SITE_FILES,
            )

    def test_visibility_marker_errors_are_rejected(self):
        expected = frozenset({"companyhub"})
        valid_markers = "<!-- repository-visibility:companyhub -->"
        invalid_pages = {
            "malformed": valid_markers + "\n<!-- repository-visibility:unknown! -->",
            "malformed_spacing": valid_markers
            + "\n<!-- repository-visibility :companyhub -->",
            "malformed_namespace_spacing": valid_markers
            + "\n<!-- repository visibility:companyhub -->",
            "malformed_closer": valid_markers
            + "\n<!-- repository-visibility:companyhub --!>",
            "malformed_case": valid_markers
            + "\n<!-- REPOSITORY-VISIBILITY:companyhub -->",
            "unknown": valid_markers + "\n<!-- repository-visibility:unknown -->",
            "duplicate": valid_markers + "\n<!-- repository-visibility:companyhub -->",
            "missing": "",
            "unexpected": valid_markers
            + "\n<!-- repository-visibility:backend-engineering-learning-journey -->",
        }
        projects = {
            "companyhub": {
                "project_id": "companyhub",
                "repository_visibility": "private",
            },
            "backend-engineering-learning-journey": {
                "project_id": "backend-engineering-learning-journey",
                "repository_visibility": "unavailable",
            },
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            page_path = Path(temporary_directory) / "projects.html"
            for name, content in invalid_pages.items():
                with self.subTest(marker_case=name):
                    page_path.write_text(content, encoding="utf-8")
                    with self.assertRaises(renderer.ConfigurationError):
                        renderer._render_page(page_path, projects, expected)

    def test_invalid_configuration_leaves_staged_html_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            site_dir = temporary_root / "site"
            site_dir.mkdir()
            for file_name in renderer.PUBLIC_SITE_FILES:
                (site_dir / file_name).write_text("", encoding="utf-8")

            page_contents = {
                "projects.html": (
                    "<!-- repository-visibility:companyhub -->\n"
                    "<!-- repository-visibility:backend-engineering-learning-journey -->"
                ),
                "engineering.html": "<!-- repository-visibility:companyhub -->",
            }
            for name, content in page_contents.items():
                (site_dir / name).write_text(content, encoding="utf-8")
            before = {
                name: (site_dir / name).read_bytes() for name in page_contents
            }

            config_path = temporary_root / "invalid-visibility.json"
            config_path.write_text("{", encoding="utf-8")

            with self.assertRaises(renderer.ConfigurationError):
                renderer.render_staged_site(site_dir, config_path)

            after = {
                name: (site_dir / name).read_bytes() for name in page_contents
            }
            self.assertEqual(after, before)

    def test_later_malformed_marker_leaves_all_staged_pages_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            site_dir = temporary_root / "site"
            site_dir.mkdir()
            for file_name in renderer.PUBLIC_SITE_FILES:
                (site_dir / file_name).write_text("", encoding="utf-8")

            (site_dir / "projects.html").write_text(
                "<!-- repository-visibility:companyhub -->\n"
                "<!-- repository-visibility:backend-engineering-learning-journey -->",
                encoding="utf-8",
            )
            (site_dir / "engineering.html").write_text(
                "<!-- repository-visibility:companyhub! -->", encoding="utf-8"
            )
            before = {
                file_name: (site_dir / file_name).read_bytes()
                for file_name in renderer.PUBLIC_SITE_FILES
            }

            config_path = temporary_root / "visibility.json"
            config_path.write_text(
                json.dumps(
                    {
                        "projects": [
                            {
                                "project_id": "companyhub",
                                "repository_visibility": "private",
                            },
                            public_entry(url="https://github.com/example/project"),
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(renderer.ConfigurationError):
                renderer.render_staged_site(site_dir, config_path)

            after = {
                file_name: (site_dir / file_name).read_bytes()
                for file_name in renderer.PUBLIC_SITE_FILES
            }
            self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
