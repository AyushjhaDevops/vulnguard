# VulnGuard

**AI-Powered DevSecOps Security and Vulnerability Prioritization Platform**

VulnGuard is a security platform designed to integrate repository security
scanning, consolidate findings, prioritize risks, assist remediation, and
enforce configurable security policies in CI/CD pipelines.

## Problem

Security findings are often distributed across independent tools. VulnGuard
aims to help developers investigate, prioritize, and remediate these findings
through one consistent workflow.

## Planned features

- GitHub repository integration
- Static application security testing with Semgrep
- Dependency, container, and infrastructure scanning with Trivy
- Secret detection with Gitleaks
- Normalized findings and scan history
- Contextual risk prioritization
- Optional local AI-assisted investigation
- Evidence-backed attack-path visualization
- Configurable GitHub Actions security gates
- Audit logs and security reports

## Planned technology stack

- Backend: Python and FastAPI
- Frontend: React, TypeScript, Vite, and Tailwind CSS
- Database: PostgreSQL
- Scanning: Semgrep, Trivy, and Gitleaks
- CI/CD: GitHub Actions
- Testing: pytest and frontend tests
- Deployment: Docker Compose

## Project status

Phase 0 — Requirements, architecture, and repository setup.

The features listed above are planned; they are not yet implemented.

## Development principles

- Scan only repositories that we own or are authorized to assess.
- Treat repository contents and scanner output as untrusted input.
- Never store or display unredacted secrets in findings.
- Keep scanner jobs isolated and resource-limited.
- Make risk assessments explainable and reproducible.
- Distinguish scan failures from clean scan results.

## Documentation

- [Project requirements](docs/PRD.md)
- [System requirements](docs/SRS.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)

## License

License selection is pending.
