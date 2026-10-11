# Product Requirements Document — VulnGuard

## 1. Product vision

Provide developers and security analysts with one workflow to detect,
understand, prioritize, and remediate software security weaknesses before
unsafe changes proceed through CI/CD.

## 2. Problem statement

Source-code, dependency, secret, container, and infrastructure scanners
often produce separate reports. Teams must correlate findings manually,
prioritize remediation, and enforce security decisions in different systems.

VulnGuard will consolidate these activities in one platform.

## 3. Target users

- Developer: reviews findings and fixes issues in authorized repositories.
- Security analyst: investigates risk, validates findings, and manages policies.
- Administrator: manages users, configuration, and platform access.

## 4. MVP scope

- User authentication and authorization.
- Authorized Git repository registration.
- Background scan orchestration.
- Semgrep source-code scanning.
- Trivy dependency and configuration scanning.
- Gitleaks secret detection.
- Unified findings and scan history.
- Dashboard, filters, and remediation status.
- Configurable CI/CD security gates.
- Audit events and safe secret redaction.

## 5. Advanced scope

- Contextual risk prioritization.
- Optional local AI explanations and remediation suggestions.
- Evidence-backed attack-path visualization.
- Container image scanning.
- Reports and remediation trend analytics.

## 6. Out of scope for the first release

- Guaranteed detection of every vulnerability.
- Autonomous production remediation.
- Unauthorized scanning of third-party systems.
- Enterprise-scale multi-tenant orchestration.
- Mandatory paid AI services.

## 7. Product principles

- Evidence first: every finding must retain its source and provenance.
- Least privilege: integrations request only necessary permissions.
- Safe by default: scan jobs are isolated and resource-limited.
- Explainable risk: show scoring factors and model limitations.
- Human review: AI suggestions are not automatically trusted or executed.
- Reproducibility: record commit SHA, scanner version, and scan status.

## 8. Success criteria

- Seeded vulnerabilities are detected by the relevant configured scanners.
- Findings are normalized and displayed with useful evidence.
- Secrets are redacted from stored presentation data and logs.
- CI/CD gates correctly enforce documented policies.
- Failed or incomplete scans cannot appear as clean scans.
- Risk assessments are reproducible and explainable.
- Core workflows are covered by automated tests.

## 9. Constraints

- Initial development targets Arch Linux.
- Prefer free and open-source tools.
- Local AI is optional and must not be required for core scanning.
- Results depend on scanner coverage, rule quality, and available vulnerability data.

## 10. Risks

- False positives and false negatives.
- Scanner version and vulnerability database changes.
- Malicious repository content.
- Exposure of source code or credentials.
- AI hallucinations and unsafe recommendations.
- Excessive scan resource consumption.

## 11. MVP completion definition

A user can register an authorized repository, launch a scan, review findings
in the dashboard, understand the policy outcome, and reproduce the workflow
using documented setup and test instructions.
