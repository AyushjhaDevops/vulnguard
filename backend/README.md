# VulnGuard Backend

FastAPI application and API layer.

Planned responsibilities:
- Authentication and authorization
- Repository registration and access checks
- Scan lifecycle and result APIs
- Database models and persistence
- Finding aggregation and risk scoring
- Audit events and report generation

Business logic belongs in services rather than large API handlers.
The API must not execute untrusted repository code.
