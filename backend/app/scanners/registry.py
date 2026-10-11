
from app.scanners.base import BaseScanner, ScannerError
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner


SCANNER_CLASSES: dict[str, type[BaseScanner]] = {
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
}


def get_scanner(name: str, *, timeout: int | None = None) -> BaseScanner:
    """Create a supported scanner by name."""
    normalized_name = name.strip().lower()
    scanner_class = SCANNER_CLASSES.get(normalized_name)

    if scanner_class is None:
        raise ScannerError(f"Unsupported scanner: {normalized_name or '(empty)'}")

    return scanner_class(timeout=timeout)


def available_scanners() -> list[dict[str, str | bool]]:
    """Report which scanner executables are available on this host."""
    results: list[dict[str, str | bool]] = []

    for name, scanner_class in SCANNER_CLASSES.items():
        scanner = scanner_class()
        results.append(
            {
                "name": name,
                "installed": scanner.is_available(),
            }
        )

    return results
