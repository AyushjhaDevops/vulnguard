
from pathlib import Path
from typing import Any

from app.scanners.base import (
    BaseScanner,
    ScanResult,
    ScannerExecutionError,
    ScannerFinding,
    normalize_severity,
    parse_json_output,
    run_command,
    validate_target,
)


class TrivyScanner(BaseScanner):
    name = "trivy"
    executable = "trivy"

    def scan(self, target: str | Path) -> ScanResult:
        target_path = validate_target(target)

        command = [
            self.executable,
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln,misconfig,secret",
            "--quiet",
            str(target_path),
        ]

        completed = run_command(
            command,
            target=target_path,
            timeout=self.timeout,
        )
        payload = parse_json_output(completed.stdout, self.name)

        if not isinstance(payload, dict):
            raise ScannerExecutionError("Trivy returned an unexpected JSON format.")

        results = payload.get("Results") or []
        if not isinstance(results, list):
            raise ScannerExecutionError("Trivy results must be a JSON list.")

        findings: list[ScannerFinding] = []

        for result in results:
            if not isinstance(result, dict):
                continue

            target_name = result.get("Target")
            if not isinstance(target_name, str):
                target_name = ""

            for category in ("Vulnerabilities", "Misconfigurations", "Secrets"):
                items = result.get(category) or []
                if not isinstance(items, list):
                    continue

                for item in items:
                    if not isinstance(item, dict):
                        continue

                    identifier = (
                        item.get("VulnerabilityID")
                        or item.get("ID")
                        or item.get("RuleID")
                        or item.get("AVDID")
                        or f"trivy.{category.lower()}"
                    )

                    title_value = item.get("Title") or item.get("Message")
                    title = str(title_value or identifier)

                    description_value = item.get("Description")
                    description = str(
                        description_value
                        or item.get("Message")
                        or title
                    )

                    raw_path = item.get("PkgPath") or item.get("FilePath")
                    if not isinstance(raw_path, str) or not raw_path:
                        raw_path = target_name or None

                    relative_path = None
                    if raw_path:
                        candidate = Path(raw_path)
                        try:
                            if not candidate.is_absolute():
                                candidate = target_path / candidate
                            relative_path = candidate.resolve().relative_to(
                                target_path
                            ).as_posix()
                        except (OSError, ValueError, RuntimeError):
                            # Some Trivy targets refer to packages rather
                            # than files. Preserve the finding, not an
                            # untrusted path outside the scan target.
                            relative_path = None

                    line = None
                    cause_metadata = item.get("CauseMetadata")
                    if isinstance(cause_metadata, dict):
                        line = cause_metadata.get("StartLine")

                    if line is None:
                        line = item.get("StartLine")

                    if not isinstance(line, int) or line < 1:
                        line = None

                    evidence: dict[str, Any] = {
                        "rule_id": str(identifier)[:256],
                        "category": category.lower(),
                    }

                    # Keep selected package metadata, not raw secret matches.
                    for source_key, evidence_key in (
                        ("PkgName", "package"),
                        ("InstalledVersion", "installed_version"),
                        ("FixedVersion", "fixed_version"),
                        ("PrimaryURL", "reference"),
                    ):
                        value = item.get(source_key)
                        if isinstance(value, str) and value:
                            evidence[evidence_key] = value[:1000]

                    # Do not copy Secret, Match, Code, or raw source snippets
                    # from Trivy secret findings into stored evidence.
                    severity = normalize_severity(item.get("Severity"))

                    findings.append(
                        ScannerFinding(
                            scanner=self.name,
                            title=title[:500],
                            description=description[:5000],
                            severity=severity,
                            file_path=relative_path,
                            line_number=line,
                            evidence=evidence,
                        )
                    )

        return ScanResult(
            scanner=self.name,
            target=str(target_path),
            findings=findings,
        )
