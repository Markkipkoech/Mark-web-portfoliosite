# AGENTS.md — Personal Portfolio Engineering Rules

## 1. Project identity

This repository contains Mark Kipkoech's personal software development portfolio.

The approved professional positioning is:

**Software Developer with a Backend Engineering Focus.**

The portfolio is intended to demonstrate genuine software development work, engineering interests, technical learning and verified project progress.

The approved website destinations are:

1. Home
2. Projects
3. Engineering
4. Learning Journal
5. Contact

The Contact page must provide both direct contact links and a working contact form.

The Services page and Bora Poultry project are excluded from the redesigned portfolio.

## 2. Strict project separation — REA exclusion

REA is a separate, independent project.

Do not use, import, reuse, adapt, reference or apply REA concepts, objectives, terminology, research, methodologies, architecture, code, documentation, prompts, instructions, configurations or workflows in this repository.

Do not introduce REA-related branding, content, functionality, dependencies, integrations or automation.

Do not assume that a decision made for REA applies to this portfolio.

Use only the approved portfolio specification, this repository's verified implementation and explicit portfolio-specific instructions.

If a requirement appears to overlap with REA, stop and request clarification.

This boundary is mandatory.

## 3. Source of truth and decision authority

Follow this order:

1. Explicit instructions from the portfolio owner.
2. Approved portfolio redesign specification.
3. These repository-specific engineering instructions.
4. Existing verified implementation and established project conventions.

Do not independently change approved product decisions.

Do not invent requirements, achievements, project functionality, professional experience or technical capabilities.

Ask for clarification when a requirement is ambiguous or materially changes scope.

The portfolio owner retains final decision authority.

## 4. Engineering approach

Keep the website static unless an approved requirement demonstrates that additional infrastructure is necessary.

Prefer semantic HTML, maintainable CSS and small, understandable JavaScript modules.

Avoid unnecessary frameworks, dependencies, abstractions and build infrastructure.

Do not introduce a backend merely to support a static portfolio.

Use reusable components or shared patterns where they materially reduce duplication without adding disproportionate complexity.

Keep pages responsive and accessible.

## 5. Content accuracy

Never fabricate:

- Work experience.
- Qualifications or certifications.
- Skill levels.
- Project completion status.
- Project functionality.
- User numbers or business outcomes.
- Performance measurements.
- Testing results.

Do not use arbitrary skill percentages.

Distinguish clearly between:

- Applied: supported by actual implementation evidence.
- Learning: currently being studied or practised.
- Exploring: an area of interest without sufficient implementation evidence.

CompanyHub must be described as in development unless its status is explicitly updated by the owner.

The Backend Engineering Learning Journey must be presented as a learning project, not as a production application.

Do not publish private CompanyHub source code, credentials, secrets, customer data, internal configurations or sensitive security and architecture details.

## 6. Git and file safety

Work only in the portfolio-redesign worktree.

Do not modify the original repository working directory or its staged changes.

Do not switch to the original main working directory to perform redesign tasks.

Never execute the following without explicit owner authorization:

- git add
- git commit
- git reset
- git stash
- git clean
- git checkout or branch operations that discard or overwrite work
- Destructive file or directory deletion
- Force pushes

Do not overwrite existing files without inspecting their contents and understanding their purpose.

Preserve unrelated changes.

Before modifying files, inspect the relevant implementation and report the intended scope.

Keep each implementation task small and bounded.

## 7. Accessibility

Use semantic HTML elements.

Use native buttons for interactive controls.

Provide accessible labels and meaningful alternative text.

Ensure keyboard navigation and visible focus indicators.

Use appropriate ARIA attributes only when necessary.

Respect prefers-reduced-motion.

Maintain readable contrast in both light and dark themes.

Do not use colour as the only way to communicate meaning.

## 8. JavaScript and CSS quality

Keep JavaScript focused on actual interface behaviour.

Avoid unnecessary global state, duplicated event listeners and brittle DOM selectors.

Use clear naming and handle failure states.

Keep CSS organized and avoid excessive specificity.

Use consistent design tokens for colours, spacing, typography and layout.

Ensure theme preference works without causing a disruptive flash or inaccessible initial render.

## 9. Contact form integrity

A contact form must actually submit messages through an approved service or endpoint.

Do not claim a message was submitted unless the submission service confirms success.

Handle validation, submission, duplicate attempts, errors and success states.

Do not expose secret API keys or private credentials in browser JavaScript.

Do not invent a form provider or endpoint.

## 10. SEO and performance

Provide meaningful page titles and descriptions.

Use appropriate social metadata and canonical URLs.

Ensure links and assets work under the GitHub Pages repository base path.

Optimize images and avoid unnecessary external dependencies.

Do not add analytics, tracking or third-party services without approval.

## 11. Testing and verification

After every bounded implementation task:

1. Inspect the diff.
2. Run relevant syntax and validation checks.
3. Test affected page behaviour.
4. Check responsive behaviour where relevant.
5. Report any failed or unperformed checks honestly.

Never claim a test passed unless it was actually executed and passed.

Do not suppress errors simply to make checks pass.

## 12. Copilot task discipline

Only perform the specific task explicitly assigned by the portfolio owner.

Do not redesign unrelated pages or introduce additional features.

Do not silently expand scope.

Before implementation, identify:

- Files expected to change.
- Intended behaviour.
- Relevant constraints.
- Verification steps.

After implementation, report:

- Files changed.
- Summary of changes.
- Important technical decisions.
- Tests executed and results.
- Known limitations.
- Any recommended follow-up work.

Stop when the assigned task is complete. Wait for review and approval before proceeding to another task.

## 13. Final principle

Build a credible, accessible, maintainable and evidence-based engineering portfolio.

Prefer correctness, clarity, simplicity, privacy and verified results over visual effects, exaggerated claims or unnecessary technical complexity.