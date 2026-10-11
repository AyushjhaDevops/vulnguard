# VulnGuard Threat Model

## Assets

- Repository source code and metadata.
- Credentials and integration tokens.
- Scan reports and vulnerability evidence.
- User accounts and authorization data.
- Security policies and audit records.

## Trust boundaries

- Browser to API.
- GitHub webhook to API.
- API to background worker.
- Worker to repository content and scanner tools.
- Backend to database.
- AI model to untrusted repository-derived context.

## Threats and initial mitigations

1. Malicious repository content:
   Run scans in restricted, disposable workers; never execute arbitrary build
   scripts with API-server privileges.

2. Credential exposure:
   Use least-privilege tokens, redact findings, avoid logging secrets, and
   keep credentials out of source control.

3. Unauthorized repository access:
   Enforce resource ownership and server-side authorization on every request.

4. Forged webhooks:
   Validate signatures, event types, and payloads.

5. Denial of service:
   Apply job limits, timeouts, concurrency limits, and request rate limits.

6. Malicious scanner output:
   Validate structured output and safely render untrusted text.

7. Prompt injection:
   Treat repository text as untrusted data; do not give the AI model authority
   to execute commands or change security policy.

8. Unsafe remediation:
   Require human review before applying patches or performing sensitive actions.

9. Incorrect security gate:
   Distinguish scanner failures from clean results and test policy behavior.

## Residual risks

Scanners can miss vulnerabilities or report false positives. AI can produce
incorrect recommendations. Findings and attack paths require validation.
The platform must communicate these limitations clearly.
