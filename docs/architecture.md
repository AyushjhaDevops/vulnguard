# VulnGuard System Architecture

## 1. Architectural style

A modular monolith for the API, with a separate restricted background worker.
This reduces initial complexity while keeping scanner execution isolated.

## 2. Components

- Frontend: React, TypeScript, Vite, Tailwind CSS.
- API: FastAPI, authentication, repository and scan endpoints.
- Database: PostgreSQL, managed through SQLAlchemy and Alembic.
- Queue: initially a simple worker; Redis/Celery can be introduced later.
- Scanners: Semgrep, Trivy, Gitleaks.
- Normalizer: common finding schema and deduplication.
- Risk engine: transparent contextual prioritization.
- Policy engine: configurable pass, warn, and fail decisions.
- AI assistant: optional local model; no mandatory paid API.
- Graph engine: NetworkX with React Flow visualization.
- CI/CD: GitHub Actions.

## 3. Data flow

1. A user registers an authorized repository.
2. A manual request or validated GitHub event creates a scan job.
3. The backend records the scan and queues work.
4. A restricted worker executes the configured scanners.
5. Scanner output is validated and normalized.
6. Findings and scan metadata are stored.
7. The risk engine assesses findings.
8. The policy engine evaluates the configured rules.
9. Results are exposed through the API and dashboard.
10. GitHub Actions receives a policy outcome where configured.

## 4. Security boundaries

- Never execute repository code in the API process.
- Treat repository files, comments, and scanner output as untrusted.
- Restrict worker filesystem, network, privileges, and resource usage.
- Redact secrets before persistence, logging, or AI processing.
- Validate webhook signatures and event payloads.
- Keep credentials outside source control.
- Require authorization for sensitive operations.
- Keep audit records for policy decisions and exceptions.

## 5. Failure handling

Scanner failure, timeout, malformed output, cancellation, and partial results
must be represented explicitly. A scan is not clean merely because a scanner
failed to run.

## 6. Deployment

The initial deployment target is local Docker Compose with a frontend, API,
restricted worker, PostgreSQL, and optionally Redis.

## 7. Architecture evolution

Begin with a single API application and a separate worker. Add more workers,
queue infrastructure, and cloud deployment only when the core workflow is
reliable and testing demonstrates the need.
