# Software Requirements Specification — VulnGuard

## 1. System components

- React frontend.
- FastAPI backend.
- Relational database.
- Background job queue and scanner worker.
- Scanner adapters.
- Finding normalization service.
- Risk assessment and policy engines.
- Optional local AI integration.
- GitHub Actions integration.

## 2. Functional requirements

FR-01: Authenticate users and authorize access to resources.
FR-02: Register authorized Git repositories.
FR-03: Create, queue, execute, and track scan jobs.
FR-04: Import results from Semgrep, Trivy, and Gitleaks.
FR-05: Normalize scanner output into a common finding schema.
FR-06: Deduplicate and track findings across scans.
FR-07: Filter findings by repository, severity, tool, and status.
FR-08: Produce reproducible contextual risk assessments.
FR-09: Provide optional evidence-grounded AI explanations.
FR-10: Visualize evidence-backed relationships between findings.
FR-11: Enforce configurable CI/CD security policies.
FR-12: Store audit events and generate scan reports.
FR-13: Distinguish successful, failed, and incomplete scans.
FR-14: Protect secret values and sensitive repository data.

## 3. Non-functional requirements

Security: least privilege, secure authentication, redaction, worker isolation.
Reliability: timeouts, retries, failure handling, and database consistency.
Performance: asynchronous scanning and paginated result queries.
Maintainability: modular services and documented interfaces.
Portability: reproducible development and containerized deployment.
Testability: automated unit, integration, and end-to-end tests.
Auditability: record scan versions, commit SHAs, policy decisions, and actors.

## 4. Initial acceptance tests

AT-01: Unauthorized requests cannot read protected resources.
AT-02: An authorized repository can be registered.
AT-03: A scan can be queued and its status retrieved.
AT-04: Seeded test findings are parsed and stored correctly.
AT-05: Secret values are redacted in displayed findings.
AT-06: A failed scanner run is not represented as a clean scan.
AT-07: Policy tests pass or fail according to configured rules.
AT-08: Repeated findings can be tracked across multiple scans.
AT-09: Core API and service behavior is covered by automated tests.

## 5. Assumptions

- GitHub integration uses authorized repositories.
- Scanner tools and vulnerability data may change between versions.
- AI output requires validation and is not security proof.
- Advanced graph relationships require supporting evidence.
