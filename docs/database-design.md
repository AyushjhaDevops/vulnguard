# VulnGuard Database Design

## Database
- SQLite is used for local development.
- SQLAlchemy 2.x provides ORM models and database sessions.
- Alembic manages schema migrations.
- Application startup does not automatically create or modify tables.

## Initial entities

### users
Stores user identity, password hashes, account status, and creation time.

### repositories
Stores repository metadata and ownership. A repository is unique by
owner, provider, and full name.

### scans
Stores scan lifecycle status, commit identifier, timestamps, and
sanitized error information.

### findings
Stores scanner findings, severity, fingerprint, location, status,
and structured evidence.

## Relationships
- One user can own multiple repositories.
- One repository can have multiple scans.
- One scan can contain multiple findings.

## Data integrity
- User email addresses are unique.
- Repository identity is unique for a given owner and provider.
- Finding fingerprints are unique within a scan.
- Scan status and finding severity are constrained.
- SQLite foreign-key enforcement is enabled by the application engine.

## Security
- Store password hashes, never plaintext passwords.
- Do not store raw secrets in finding evidence.
- Avoid logging database credentials.
- Keep local database files out of version control.

## Migration workflow
1. Modify SQLAlchemy models.
2. Generate a migration with `alembic revision --autogenerate`.
3. Review the generated migration.
4. Apply with `alembic upgrade head`.
5. Test schema and application behavior.
