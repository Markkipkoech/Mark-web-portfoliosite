# Portfolio publishing data

This directory defines the data contract for potential project updates to the portfolio. A validation-only command-line tool is implemented; submission intake and publishing automation are not.

## Project registry

`projects/registry.json` is the allowlist of project repositories that may submit updates for consideration. Each entry identifies the exact repository, its portfolio display name, whether it is enabled, and the portfolio destinations to which updates for that project may be considered.

An update identifies a project by its exact registry key (`project_id`), not by supplying an arbitrary repository name. Its destination must be permitted for that project in the registry.

## Update schema

`schemas/portfolio-update.schema.json` describes the expected shape and limits of a project update using JSON Schema Draft 2020-12. It requires the update's project identifier, date, category, content, technologies, evidence links, and proposed destination. Unknown fields are not allowed.

## Candidate validation

Run the validator with one candidate JSON file:

```text
python portfolio-data/scripts/validate_portfolio_update.py path/to/candidate.json
```

The registry, schema, and approved-update history are resolved relative to the repository root. The candidate path is supplied to the command. The validator is read-only: it does not change the candidate or portfolio data.

The validation command strictly parses candidate, schema, registry, and approved-history JSON, rejecting duplicate object keys and non-standard constants such as `NaN` and `Infinity`. It checks the candidate against the Draft 2020-12 schema with format checking enabled, checks registry authorization and the project's allowed destination, rejects whitespace-only text values, and checks evidence URLs for HTTPS, a valid hostname, a valid port when supplied, and absence of embedded credentials. These URL syntax checks do not establish that evidence is genuine, relevant, accessible, or owned by the submitting project.

The approved-history directory must exist. An existing empty directory is valid; a missing directory or malformed, unreadable, invalid, or unsafe history record fails validation. The validator is read-only and does not approve a candidate or authorize publication.

The `jsonschema` package must be available in the validation environment. If it is unavailable, the command reports the missing dependency and exits with code `2`; no weaker fallback is used.

## Approved trusted intake contract

The approved V1 design is documented in [`docs/candidate-submission-contract.md`](docs/candidate-submission-contract.md). Candidate files use `.portfolio/updates/<update_id>/candidate-NNN.json` in registered source repositories, with only each repository's default branch eligible. A central discovery workflow is intended to run every six hours and support manual `workflow_dispatch` recovery. A dedicated GitHub App will use read-only Contents access, and a dedicated private intake repository will hold candidate snapshots and trusted records.

The contract separates four concepts: exact-byte candidate snapshots, canonical submissions, trusted source observations, and append-only lifecycle events. Snapshot identity uses raw SHA-256; submission identity uses the existing Stage 1 deterministic identity contract; observation identity uses registered repository ID, exact source commit SHA, candidate path, and raw SHA-256. Formatting-only changes retain the submission ID while producing a distinct raw snapshot and observation. Changed canonical content under the same project/update pair is a linked revision that requires fresh review.

Validation, explicit human decision, and publication are separate state dimensions. Each candidate revision receives one private review pull request. Approval, rejection, or withdrawal requires an explicit human decision; closing a review pull request without merging is not rejection. Approved content requires a separate public-safe projection and promotion pull request before the existing static site can publish it.

The approved retention rule keeps snapshots, provenance, submissions, validation outcomes, human decisions, publication outcomes, and decision-reconstruction audit history for the operational lifetime of the pipeline. Routine operational telemetry is retained for 12 months. Suspected secrets or sensitive customer information are screened before persistence, kept out of routine records and logs, and handled through restricted sanitized incident metadata, source correction verified on the default branch, and rediscovery. Screening does not replace human review; forensic material has a separately owner-approved retention period.

This is an approved design, not implemented automation. The current registry does not yet contain numeric GitHub repository IDs; trusted intake must remain unavailable until owner-approved IDs are added and verified. No workflow, GitHub App, private intake repository, review/promotion automation, or public projection is created by the current validation-only tool.

### Approved-update history format

Each `.json` file under `portfolio-data/updates/approved/` represents exactly one approved update for the current local validator. It must be a top-level JSON object containing non-empty string fields `project_id` and `update_id`. The validator scans nested directories and rejects malformed or unreadable records and invalid record entries rather than silently skipping them. This ledger remains an input to that validator, but it is not the future pipeline's authoritative submission, revision, approval, or lifecycle store. Once the pipeline is implemented, its private intake repository's append-only records will be authoritative. The validator and ledger remain unchanged during this documentation stage.

### Exit codes

- `0`: the candidate passes validation and may proceed to human review. It is not approved for publication.
- `1`: validation or configuration failure.
- `2`: the required `jsonschema` dependency is unavailable.

## Review and publication

Candidate validation is not human approval. Passing schema and registry checks does not establish that evidence supports the claimed update or that its content is safe and accurate. Human review must assess evidence quality and content. Only the central portfolio review process can authorize publication.

Submitted information must be accurate, publicly safe, and supported by evidence that can be reviewed. Do not include private source code, credentials, customer data, or sensitive internal details. CompanyHub remains in development, and the Backend Engineering Learning Journey must be described as a learning project.

## Public repository visibility

`../public-project-visibility.json` is a separate, deliberately public-safe presentation configuration. It contains only existing project IDs, repository visibility (`public`, `private`, or `unavailable`), and an approved public repository URL for `public` projects. It is not the submission authorization registry and does not establish project ownership.

Candidate updates cannot set repository visibility or authorize a repository URL. The existing candidate schema remains unchanged and rejects additional fields. Do not publish the raw submission registry if it contains private source identifiers or trusted authorization mappings.

The Pages workflow first copies its explicit website-file allowlist to a temporary staging directory, then runs `../scripts/render_repository_visibility.py` to render visibility markers in project cards and relevant project pages. Only the rendered allowlisted website files are uploaded; the raw registry, candidate records, schemas, validator, documentation, and backup directories are not included. `unavailable` renders neither a repository link nor a private-source notice.

The renderer checks URL structure, not live GitHub accessibility or project ownership. Verify an approved repository URL and its relationship to the project before adding it to the public presentation configuration.

## Future automation

The following integrations are not yet implemented:

- GitHub Actions intake.
- Cross-repository communication.
- Automated pull request creation.
- An approval workflow.
- Deployment integration.

The validator only checks a candidate file; it does not submit updates, approve them, publish content, or deploy website changes.
