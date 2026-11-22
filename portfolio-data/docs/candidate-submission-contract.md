# Portfolio candidate submission and trusted intake contract

## Purpose and implementation status

This document defines the project-authored candidate format and the approved V1 trusted-intake contract. The candidate schema, registry, deterministic identity implementation, approved-history duplicate checks, and validation-only command exist today. Scheduled discovery, private intake storage, provenance capture, lifecycle management, human review automation, public-safe projection, and promotion are not implemented by those tools.

The approved pipeline is designed around a dedicated private intake repository. A central workflow will discover candidates every six hours and support manual `workflow_dispatch` recovery. It will use a dedicated GitHub App with read-only Contents access to registered source repositories. Only candidates on each source repository's default branch are eligible. The central intake will create one private review pull request per candidate revision. Validation is separate from explicit human approval, rejection, or withdrawal. Approved content will be transformed into a separate public-safe projection and proposed through a separate promotion pull request. The existing static portfolio and GitHub Pages remain the publishing platform. No candidate or intake record directly deploys website content.

## Project-authored candidate JSON

Candidate files use this exact convention in a registered source repository:

```text
.portfolio/
└── updates/
    └── <update_id>/
        ├── candidate-001.json
        ├── candidate-002.json
        └── candidate-003.json
```

Only direct child directories of `.portfolio/updates/` are permitted, and each directory name must equal the candidate's `update_id`. Eligible files are only `candidate-NNN.json`, where `NNN` is a three-digit positive, zero-padded sequence number. Each committed candidate file is immutable. Every new byte-level version gets a new sequence number, including formatting-only changes. Canonical content changes create linked submission revisions; formatting-only changes create new snapshots and observations attached to the same submission. Invalid, duplicate, or conflicting files are excluded from normal intake and handled through the restricted error/incident process. No other filename convention is permitted.

Candidate paths are repository-relative and must use `/` separators. They must begin exactly with `.portfolio/updates/`, contain no absolute prefix, `.` or `..` segments, repeated separators, or backslashes, and use lowercase ASCII directory and filename components. Matching is case-sensitive. The path must match the convention above and reference a regular Git-tree file, not a symlink. Reject noncanonical paths; never rewrite them into an eligible path. A candidate's `project_id` and `update_id` identify its claimed project milestone, not its source or delivery provenance.

The candidate contains only fields allowed by `portfolio-data/schemas/portfolio-update.schema.json`, whose `additionalProperties: false` rule rejects extra properties. Candidate JSON must not author trusted source identity, source branch or commit, candidate path, workflow identity, timestamps, App identity, validation result, approval, withdrawal, publication state, or revision relationships.

### Candidate fields

| Field | Contract |
|---|---|
| `schema_version` | String fixed at `"1.0"`. This is distinct from the identity-contract version. |
| `project_id` | Exact project key from `portfolio-data/projects/registry.json`. It is a claim checked against the authenticated source repository. |
| `update_id` | 1–64 lowercase letters, digits, or hyphens; begins with a letter or digit. It identifies a milestone within its project. |
| `date` | ISO date (`YYYY-MM-DD`) on which the described milestone was completed. |
| `category` | One of `feature`, `integration`, `engineering`, `milestone`, or `learning`. |
| `title` | Factual milestone title, 1–120 characters. |
| `summary` | Concise factual description, 1–500 characters. |
| `highlights` | 1–8 factual strings, each 1–240 characters. |
| `technologies` | 1–12 distinct technologies actually used, each 1–50 characters. |
| `evidence` | 1–8 distinct HTTPS URI strings, each at most 500 characters. Syntax validation does not establish that evidence is genuine, relevant, accessible, or owned by the project. |
| `destination` | One of `projects`, `engineering`, or `learning-journal`, also permitted for that project by the registry. |

The existing schema and validator define the detailed formats and limits. The current registry has repository owner/name mappings but does not yet contain numeric GitHub repository IDs. Before trusted intake is enabled, the registry must be extended with owner-approved numeric repository IDs and those IDs must be verified against GitHub repository metadata. Until then, intake must fail closed rather than infer or accept an ID from candidate content.

## Four-part trusted intake data model

These are separate record concepts. Candidate bytes are untrusted input; the other records are generated by the central intake system. Candidate-authored JSON never supplies or overrides provenance, identity, lifecycle, or review metadata.

### 1. Candidate snapshot

A snapshot holds the exact candidate byte sequence read from the trusted source commit, without newline, whitespace, encoding, or key-order normalization. It records:

- Immutable private blob reference.
- Raw SHA-256 of the exact bytes.
- Exact byte length.
- Parsed `schema_version`, `project_id`, and `update_id` where safely available.
- Canonical SHA-256 and Stage 1 submission ID where the Stage 1 identity function can produce them.

The snapshot identity is the raw SHA-256 (represented as `sha256:<hex>`). Every distinct raw byte sequence is retained as its own snapshot, including formatting-only changes. If parsing or identity derivation fails, retain a safe snapshot only if it passes the sensitive-data pre-persistence gate; record the raw digest and length, and mark parsed identity unavailable. Suspected sensitive content is handled under the separate incident policy below and is not copied to routine snapshot storage.

### 2. Submission

A submission represents a canonical candidate identity and its review lifecycle. Its stable ID is the Stage 1 deterministic submission ID. It records:

- Identity contract version (`"1"`), separate from candidate schema version (`"1.0"`).
- `submission_id`, `canonical_sha256`, `project_id`, and `update_id`.
- References to one or more raw snapshots and source observations.
- Revision relationships to earlier or later submissions for the same `(project_id, update_id)`.
- Current validation, human-decision, and publication dimensions as rebuildable projections of append-only lifecycle events.

Do not mutate a submission's identity fields or silently replace one of its snapshot references. A new canonical content digest creates a new submission, even when the project/update pair is unchanged.

### 3. Source observation

An observation records a trusted discovery of a snapshot from a registered source. It includes:

- Registered source repository full name and numeric repository ID.
- Source default branch name and exact source commit SHA.
- Candidate file path, which must match the approved `.portfolio/updates/` path policy.
- Central workflow run ID and URL.
- First-seen UTC timestamp and snapshot reference.
- Verified central GitHub App identity (App and installation identifiers; never credentials).
- Validator version, schema reference, and validation outcome/error codes.

The source commit must be resolved from trusted GitHub context and the file read from that exact commit. The candidate path must be discovered under the approved path policy, not supplied as authoritative provenance by JSON. Only the repository's default branch is eligible.

### 4. Lifecycle events

Append-only lifecycle events record validation outcomes, human decisions, promotion attempts, publication results, and recovery events needed to reconstruct processing decisions. Each event references the submission and, where applicable, observation or snapshot. It records UTC time, event type, actor kind and verified identity, prior/new dimension values, a stable reason/result code, and trusted workflow or review references. Do not place candidate payloads, credentials, suspected secrets, or sensitive customer information in event details. Routine diagnostic detail belongs in operational telemetry, not the lifecycle audit.

The current state is derived from events. Any materialized state file or index is a rebuildable convenience and must not replace the event history as the record of decisions.

## Identity and deduplication rules

The three identities are deliberately independent:

1. **Snapshot identity:** `sha256:<raw_sha256>` identifies exact candidate bytes.
2. **Submission identity:** the Stage 1 ID is derived from identity-contract version `"1"`, `project_id`, `update_id`, and canonical candidate SHA-256 using the established deterministic identity function. Source commit, workflow run, timestamp, and formatting do not enter this ID.
3. **Observation identity:** SHA-256 over the RFC 8785 canonical JSON representation of the following object, with exactly these keys and values:

   ```json
   {
     "candidate_path": ".portfolio/updates/example-update/candidate-001.json",
     "raw_sha256": "<64 lowercase hex characters>",
     "source_commit_sha": "<full commit SHA>",
     "source_repository_id": 123456789
   }
   ```

   The observation ID is represented as `sha256:<hex>`. `source_repository_id` is the numeric ID pinned in the central registry and verified against trusted GitHub metadata. `candidate_path` is the already-validated path exactly as stored in the Git tree; do not normalize or rewrite it before identity calculation. Workflow run ID and observed timestamp are excluded so a retry of the same repository/commit/path/bytes has the same observation identity. The first durable observation records the workflow run; later retry/recovery attempts are separate lifecycle events referencing that observation, with their own run IDs and timestamps.

The Stage 1 implementation remains the authority for the submission ID calculation and canonicalization. Formatting-only changes therefore produce a new raw snapshot and a new observation, but retain the same canonical submission ID. The same bytes seen at a different source commit have the same snapshot and submission identities but a different observation identity.

Use create-if-absent writes for immutable raw snapshots, submissions, and observations. If an existing ID is encountered, recompute and compare all identity inputs. Any mismatch is an integrity conflict: stop intake and do not open or update a review PR. Concurrent discovery of the same observation converges on one observation; each distinct workflow retry may be captured as an event.

## Revision rules

- A changed canonical candidate creates a new submission ID and a linked revision, even if it reuses the same `project_id` and `update_id`.
- The new revision requires complete validation and fresh human review. Prior approval does not carry forward.
- Keep every earlier snapshot, submission, decision, and audit event immutable. Never replace an earlier candidate or decision.
- A formatting-only byte change is a new raw snapshot/observation attached to the existing canonical submission, not a new canonical revision.
- A new `update_id` is a separate milestone submission.
- Re-observing an already approved or rejected canonical submission does not reopen it or bypass its decision. A correction is a new linked revision.
- Closing a review pull request without merging is not rejection or withdrawal. It leaves the human decision pending unless an authorized human records an explicit decision.

## Trusted provenance sources

| Field | Source and rule |
|---|---|
| Repository full name | Central registry matched to authenticated GitHub repository metadata. |
| Numeric repository ID | Owner-approved numeric ID in the central project registry, verified against GitHub repository metadata. |
| Source default branch | GitHub repository metadata captured by central discovery. Verify the observed commit belongs to the resolved default branch at discovery. |
| Exact source commit SHA | Trusted branch/ref resolution at discovery; fetch the candidate bytes from that pinned commit. Never accept a candidate-supplied SHA. |
| Candidate path | Central enumeration and path validation under `.portfolio/updates/`; preserve the exact validated repository-relative path stored in the Git tree. |
| Workflow run ID and URL | Central Actions run context. Construct the URL from trusted repository/server/run context. |
| First-seen UTC timestamp | Central UTC clock at the first durable observation write; not candidate `date`. |
| GitHub App identity | Verified central App and installation context used for the read-only source request. Do not persist tokens or private keys. |
| Validator version | Central validator source commit/version plus schema identifier/version. Record the exact validator used for each result. |
| Validation result | Central validator result (`pending`, `passed`, or `failed`) and sanitized stable error codes. |
| Project/update/schema identity | Parsed from candidate bytes and validated against schema and authenticated repository-to-project registry mapping. These remain candidate claims, not provenance. |

Missing, inconsistent, or unverifiable provenance fails closed. The current validation CLI validates a local candidate only; it does not authenticate any of these sources.

## Lifecycle dimensions and transitions

Validation, human decision, and publication are independent dimensions. Do not collapse validation success into approval or publication.

| Dimension | Values | Permitted transitions |
|---|---|---|
| Validation | `pending`, `passed`, `failed` | `pending` → `passed` or `failed` only when the validator executes. `failed` means the validator identified candidate or contract violations. Infrastructure, runner, or API failures do not change validation state; record a separate operational failure event in routine telemetry. Infrastructure retries do not create candidate revisions. Preserve every completed validation result, including results from earlier validator versions. Corrected candidate bytes create a new revision rather than resetting a failed record. |
| Human decision | `pending`, `approved`, `rejected`, `withdrawn` | `pending` → one explicit authorized decision. Decisions are terminal for that submission. A later correction is a new revision with a fresh pending decision. No decision is inferred from PR closure or source deletion. |
| Publication | `not_eligible`, `pending_promotion`, `promotion_failed_retryable`, `promoted`, `published` | `not_eligible` → `pending_promotion` only after validation passed and explicit approval. Promotion attempts may remain pending, fail retryably, or succeed as `promoted` after the separate public-safe promotion PR merges. `promotion_failed_retryable` → `pending_promotion` on an explicit retry. `promoted` → `published` only after the publishing workflow confirms successful Pages deployment. |

Rejected or withdrawn submissions remain ineligible for promotion. Promotion failure does not revoke human approval. Retry the promotion from the approved public-safe projection without changing the candidate snapshot or decision. A failed or interrupted workflow emits a lifecycle recovery event when needed to explain a durable state or decision, and resumes idempotently from the last durable step. Detailed runner/API diagnostics remain operational telemetry. If an external PR operation may have succeeded but its response was lost, reconcile remote state before retrying to avoid duplicate PRs.

Each candidate revision receives one private review PR. A distinct public-safe projection and separate promotion PR are required after explicit approval. Review PR closure without merge leaves the decision pending; an authorized human must explicitly reject or withdraw. Reopening/reconsidering a terminal decision is not implicit: use a new linked revision and fresh review unless the owner later approves a separate reopening policy.

## Sensitive-data policy

Before any routine snapshot, provenance, log, or PR persistence, scan candidate bytes for suspected secrets and sensitive customer information. Scanning is a screening measure, not proof that content is safe; human review remains mandatory before approval and publication.

When a scan flags possible sensitive information:

1. Do not copy the candidate bytes or sensitive values into routine snapshots, provenance records, logs, pull requests, or public records.
2. Only the portfolio owner and explicitly designated incident handlers may access incident records. Record sanitized incident metadata only: stable incident/reference ID, source repository ID, commit/path references where safe, detection time, scanner/version, and a generic reason code. Never copy matched values or surrounding sensitive content into ordinary logs, pull requests, snapshots, or incident summaries.
3. Block review and promotion. The source project owner is responsible for correcting the source. An incident handler must verify the correction on the default branch before rediscovery.
4. Rediscover from the corrected default branch at its new exact commit. This creates a new observation; changed canonical content creates a linked new submission revision requiring fresh validation and human review.
5. Store any necessary forensic material separately with restricted access and an explicitly owner-approved retention period. Do not invent or infer that period.

If sensitive data is found after routine persistence, stop further propagation and publication, restrict access, and initiate incident handling. Never silently rewrite audit history. Removing a candidate from the latest source commit does not necessarily remove it from Git history; incident handling must account for that history. Apply the separate forensic-material policy above.

## Retention, audit, and recovery

- Retain candidate snapshots, trusted provenance and source observations, submission identities and revision relationships, validation outcomes, human decisions, promotion and publication outcomes, and audit history necessary to reconstruct decisions for the operational lifetime of the pipeline.
- Retain routine operational telemetry for 12 months: discovery polling records, retry diagnostics, runner and API operational logs, transient infrastructure failure details, and routine performance/operational telemetry. Lifecycle and audit records do not expire merely because automation generated them. Sensitive-data incident material is governed separately and must not be copied into routine telemetry.
- Keep lifecycle events append-only and snapshots immutable. Access to the private intake repository and incident records must be limited to authorized maintainers; the public site receives only the approved public-safe projection.
- Preserve validation failures and explicit decisions as history. Do not place failed or pending submissions into public artifacts.
- Make discovery, snapshot creation, validation, review-PR creation, promotion-PR creation, and publication reconciliation idempotent. Retain concise recovery audit events needed to explain durable state or decisions; keep detailed failure and retry diagnostics in 12-month operational telemetry. Retries must not duplicate records or decisions.
- A transient API, runner, or deployment failure is an operational failure, not candidate rejection. Retry or resume from the last durable step and append the outcome.

## Validation and current implementation

The existing validator checks one local candidate against the Draft 2020-12 schema, registry authorization, allowed destination, strict JSON parsing, evidence URL syntax, and approved-history duplicate pairs. The `portfolio-data/updates/approved/` directory is an input to this current local validator only. It is not the future pipeline's authoritative submission, revision, approval, or lifecycle store. Once implemented, the private intake repository's append-only records will be authoritative for those pipeline records. This documentation change does not change the validator or ledger. The current validator does not discover candidates, verify trusted provenance, scan for secrets, manage revisions across pending/rejected submissions, create PRs, record lifecycle events, approve candidates, create public projections, or deploy content.

Run the current validation-only command with:

```text
python portfolio-data/scripts/validate_portfolio_update.py path/to/candidate.json
```

Exit code `0` means the local candidate passes these checks and may proceed to human review; it does not mean the candidate has been approved or is eligible for publication. The `jsonschema` package must be available; absence is reported with exit code `2` without a weaker fallback.

## Portfolio accuracy and privacy

Do not include credentials, tokens, private source code, customer or personal data, private internal configuration, sensitive security or architecture details, or unsupported business, partnership, performance, or outcome claims in public content. CompanyHub remains in development. Do not imply Safaricom or KRA partnerships or that CompanyHub replaces their services. Describe the Backend Engineering Learning Journey as a learning and practical engineering development repository, not a production application.

The examples under `portfolio-data/examples/` are illustrative only. They do not prove approval or publication. Evidence URL syntax checks do not establish that evidence is genuine, relevant, accessible, or owned by the submitting project.
