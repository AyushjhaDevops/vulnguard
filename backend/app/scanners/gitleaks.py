
import json
import tempfile
from pathlib import Path
from typing import Any

from app.scanners.base import (
    BaseScanner,
    ScanResult,
    ScannerExecutionError,
    ScannerFinding,
    normalize_severity,
    run_command,
    validate_target,
)


class GitleaksScanner(BaseScanner):
    name = "gitleaks"
    executable = "gitleaks"

    def scan(self, target: str | Path) -> ScanResult:
        target_path = validate_target(target)

        with tempfile.TemporaryDirectory(
            prefix="vulnguard-gitleaks-"
        ) as temp_dir:
            report_path = Path(temp_dir) / "report.json"

            command = [
                self.executable,
                "dir",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                str(target_path),
            ]

            # Exit code 1 indicates findings in standard Gitleaks behavior.
            run_command(
                command,
                target=target_path,
                timeout=self.timeout,
                allowed_exit_codes={0, 1},
            )

            try:
                if not report_path.is_file():
                    raise ScannerExecutionError(
                        "Gitleaks did not produce its JSON report."
                    )

                report_text = report_path.read_text(encoding="utf-8")
                payload: Any = (
                    json.loads(report_text) if report_text.strip() else []
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise ScannerExecutionError(
                    "Gitleaks produced an unreadable JSON report."
                ) from exc

        if not isinstance(payload, list):
            raise ScannerExecutionError(
                "Gitleaks returned an unexpected JSON format."
            )

        findings: list[ScannerFinding] = []

        for item in payload:
            if not isinstance(item, dict):
                continue

            rule_id = str(item.get("RuleID") or "gitleaks.unknown")
            relative_path = None

            raw_path = item.get("File")
            if isinstance(raw_path, str) and raw_path:
                candidate = Path(raw_path)

                try:
                    if not candidate.is_absolute():
                        candidate = target_path / candidate

                    relative_path = candidate.resolve().relative_to(
                        target_path
                    ).as_posix()
                except (OSError, ValueError, RuntimeError):
                    relative_path = None

            line = item.get("StartLine")
            if not isinstance(line, int) or line < 1:
                line = None

            # Never persist the actual secret or matching source text.
            evidence = {"rule_id": rule_id}

            for source_key, evidence_key in (
                ("Commit", "commit"),
                ("Author", "author"),
                ("Date", "date"),
            ):
                value = item.get(source_key)
                if isinstance(value, str) and value:
                    evidence[evidence_key] = value[:256]

            findings.append(
                ScannerFinding(
                    scanner=self.name,
                    title=f"Potential secret detected: {rule_id}"[:500],
                    description=(
                        "Gitleaks detected a potential exposed secret. "
                        "Review the affected file securely and rotate any "
                        "credential confirmed to be exposed."
                    ),
                    severity=normalize_severity("high"),
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
