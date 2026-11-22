# Approved update history

This directory stores approved portfolio update JSON records used to detect
duplicate `(project_id, update_id)` pairs. An empty directory is valid, but the
directory itself must exist; the validator fails closed if it is missing.

Each `.json` file must contain one top-level update object with non-empty
`project_id` and `update_id` fields. Nested update records, duplicate JSON keys,
symbolic links, non-regular files, duplicate pairs, records larger than 1 MiB,
and JSON nested deeper than 100 levels are rejected. No approved records are
currently included.
