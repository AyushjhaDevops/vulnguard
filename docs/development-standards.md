# VulnGuard Development Standards

## 1. Architecture
- Keep the backend, frontend, and scanner worker logically separated.
- Use small modules with clear responsibilities.
- Keep API handlers thin; business logic belongs in services.
- Access persistent data through database/session abstractions.
- Do not run untrusted repository code inside the API process.

## 2. Python
- Use a project virtual environment.
- Follow PEP 8 naming conventions.
- Add type hints to application functions where practical.
- Keep configuration and secrets outside source code.
- Write automated tests for important business logic.
- Use structured logging; never log credentials or raw secrets.

## 3. Frontend
- Use TypeScript for application code.
- Prefer reusable, accessible React components.
- Keep API access separate from presentation components.
- Display loading, empty, success, and error states.
- Never put server-side secrets in frontend environment variables.

## 4. Security
- Apply least privilege to users, tokens, processes, and files.
- Validate all externally supplied input.
- Authorize repository access before starting a scan.
- Verify webhook signatures before trusting webhook payloads.
- Apply timeouts and resource limits to scanner jobs.
- Treat source code, scanner output, and AI-generated suggestions as untrusted.
- Redact secrets from logs, API responses, and reports.
- Never mark a scan clean when a required scanner fails.
- Require human review before applying suggested remediation.

## 5. Testing
- Unit tests cover isolated business logic.
- Integration tests cover interactions between components.
- Test both successful and failure paths.
- Do not use real credentials in tests.
- Tests must not depend on production systems.

## 6. Git workflow
- Use short, descriptive branch names.
- Make small, focused commits.
- Run relevant tests before pushing.
- Never commit .env files, credentials, tokens, private keys,
  personal data, or unredacted scan artifacts.

## 7. Configuration
- Document required environment variables in .env.example.
- Keep real local configuration in ignored .env files.
- Validate required settings at application startup.
- Avoid production secrets in development defaults.

## 8. Reliability
- Apply explicit timeouts to network and scanner operations.
- Record scan status and failure reasons.
- Keep errors actionable without leaking sensitive information.
- Make background jobs observable and safely retryable.
