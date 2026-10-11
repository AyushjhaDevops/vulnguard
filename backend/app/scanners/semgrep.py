
from pathlib import Path

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


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    executable = "semgrep"

    def scan(self, target: str | Path) -> ScanResult:
        target_path = validate_target(target)

        command = [
            self.executable,
            "scan",
            "--json",
            "--metrics=off",
            "--config=p/default",
            str(target_path),
        ]

        completed = run_command(
            command,
            target=target_path,
            timeout=self.timeout,
        )

        payload = parse_json_output(completed.stdout, self.name)

        if not isinstance(payload, dict):
            raise ScannerExecutionError(
                "Semgrep returned an unexpected JSON format."
            )

        results = payload.get("results", [])

        if not isinstance(results, list):
            raise ScannerExecutionError(
                "Semgrep results must be a JSON list."
            )

        findings: list[ScannerFinding] = []

        for item in results:
            if not isinstance(item, dict):
                continue

            extra = item.get("extra") or {}
            if not isinstance(extra, dict):
                extra = {}

            metadata = extra.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}

            start = item.get("start") or {}
            if not isinstance(start, dict):
                start = {}

            line = start.get("line")
            if not isinstance(line, int) or line < 1:
                line = None

            # Resolve paths relative to the requested scan target.
            path_value = item.get("path")
            relative_path = None

            if isinstance(path_value, str) and path_value:
                candidate = Path(path_value)

                try:
                    if not candidate.is_absolute():
                        candidate = target_path / candidate

                    relative_path = candidate.resolve().relative_to(
                        target_path
                    ).as_posix()
                except (OSError, ValueError, RuntimeError):
                    relative_path = None

            check_id = str(
                item.get("check_id") or "semgrep.unknown"
            )

            title = str(
                metadata.get("shortDescription") or check_id
            )

            description = str(
                extra.get("message") or title
            )

            evidence = {
                "rule_id": check_id,
            }

            cwe = metadata.get("cwe")
            if isinstance(cwe, (str, list)):
                evidence["cwe"] = cwe

            references = metadata.get("references")
            if isinstance(references, list):
                evidence["references"] = [
                    ref
                    for ref in references
                    if isinstance(ref, str)
                ][:10]

            findings.append(
                ScannerFinding(
                    scanner=self.name,
                    title=title[:500],
                    description=description[:5000],
                    severity=normalize_severity(
                        extra.get("severity")
                    ),
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
