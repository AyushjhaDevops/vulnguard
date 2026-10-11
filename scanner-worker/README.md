# VulnGuard Scanner Worker

Separate execution environment for security scanning jobs.

Planned responsibilities:
- Receive authorized scan jobs
- Run approved scanner adapters with limits
- Capture exit codes, timeouts, and sanitized output
- Normalize scanner results
- Report scan status and findings to the application

Security requirements:
- Never execute a repository's own scripts as part of scanning.
- Do not run scanner jobs with unnecessary host privileges.
- Restrict filesystem and network access.
- Enforce resource limits and execution timeouts.
- Treat all repository files and scanner output as untrusted.
