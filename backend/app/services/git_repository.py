"""Safe Git checkout utilities for VulnGuard scans."""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.services.repository import (
    RepositoryInputError,
    parse_repository_url,
)


DEFAULT_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 600
DEFAULT_MAX_CHECKOUT_MB = 500
MAX_BRANCH_LENGTH = 255


class GitCheckoutError(RuntimeError):
    """Raised when a repository cannot be checked out safely."""


@dataclass(frozen=True)
class GitCheckout:
    workspace: Path
    commit_sha: str


def _workspace_root() -> Path:
    configured = os.environ.get("VULNGUARD_WORKSPACE_ROOT")
    if configured:
        root = Path(configured).expanduser()
    else:
        root = Path(__file__).resolve().parents[2] / "workspaces"

    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    if not root.is_dir():
        raise GitCheckoutError("The configured workspace root is invalid.")

    return root


def _validate_branch(branch: str) -> str:
    """Reject malformed or option-like Git branch names."""

    if not isinstance(branch, str):
        raise GitCheckoutError("Invalid branch name.")

    branch = branch.strip()

    if (
        not branch
        or len(branch) > MAX_BRANCH_LENGTH
        or branch.startswith("-")
        or branch.startswith("/")
        or branch.endswith("/")
        or branch.endswith(".")
        or ".." in branch
        or "@{" in branch
        or branch == "@"
        or any(ord(char) < 32 or ord(char) == 127 for char in branch)
        or any(char in branch for char in " ~^:?*[\\")
        or any(part.startswith(".") or part.endswith(".lock")
               for part in branch.split("/"))
    ):
        raise GitCheckoutError("Invalid branch name.")

    return branch


def _run_git(
    arguments: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run Git without a shell or interactive credential prompts."""

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GCM_INTERACTIVE"] = "Never"

    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitCheckoutError("Git operation timed out.") from exc
    except OSError as exc:
        raise GitCheckoutError("Git could not be started.") from exc


def _directory_size_bytes(directory: Path) -> int:
    total = 0

    for current, _, filenames in os.walk(directory, followlinks=False):
        for filename in filenames:
            path = Path(current) / filename

            try:
                if path.is_symlink():
                    continue
                total += path.stat().st_size
            except OSError as exc:
                raise GitCheckoutError(
                    "Could not verify checkout size."
                ) from exc

    return total


def checkout_repository(
    *,
    owner_id: int,
    repository_id: int,
    scan_id: int,
    clone_url: str,
    branch: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_checkout_mb: int = DEFAULT_MAX_CHECKOUT_MB,
) -> GitCheckout:
    """Clone one branch into a unique workspace and return its commit SHA.

    The clone is shallow to avoid downloading unnecessary Git history.
    A checkout that exceeds the configured size limit is removed.
    """

    if min(owner_id, repository_id, scan_id) < 1:
        raise GitCheckoutError("Invalid checkout identifiers.")

    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise GitCheckoutError("Invalid Git timeout configuration.")

    if not 1 <= max_checkout_mb <= 10_000:
        raise GitCheckoutError("Invalid checkout size configuration.")

    branch = _validate_branch(branch)

    try:
        _, _, normalized_url = parse_repository_url(clone_url)
    except (RepositoryInputError, TypeError, AttributeError) as exc:
        raise GitCheckoutError("Unsupported or invalid repository URL.") from exc

    root = _workspace_root()
    parent = (root / str(owner_id) / str(repository_id)).resolve()

    if not parent.is_relative_to(root) or parent == root:
        raise GitCheckoutError("Invalid checkout workspace path.")

    parent.mkdir(parents=True, exist_ok=True)

    workspace: Path | None = None

    try:
        workspace = Path(
            tempfile.mkdtemp(prefix=f"scan-{scan_id}-", dir=parent)
        ).resolve()

        if not workspace.is_relative_to(root) or workspace == root:
            raise GitCheckoutError("Invalid checkout workspace path.")

        # Prevent Git from using local or external-helper protocols.
        # Disable redirects so the configured HTTPS host cannot silently
        # redirect Git to a different destination.
        clone_result = _run_git(
            [
                "-c", "protocol.file.allow=never",
                "-c", "protocol.ext.allow=never",
                "-c", "http.followRedirects=false",
                "clone",
                "--depth", "1",
                "--single-branch",
                "--no-tags",
                "--branch", branch,
                "--",
                normalized_url,
                str(workspace),
            ],
            timeout=timeout_seconds,
        )

        if clone_result.returncode != 0:
            # Do not return Git output; it can contain sensitive diagnostics.
            raise GitCheckoutError(
                "Repository checkout failed. Verify repository access and branch."
            )

        actual_size = _directory_size_bytes(workspace)
        max_size = max_checkout_mb * 1024 * 1024

        if actual_size > max_size:
            raise GitCheckoutError(
                "Repository checkout exceeds the configured size limit."
            )

        result = _run_git(
            ["rev-parse", "--verify", "HEAD"],
            timeout=min(timeout_seconds, 30),
            cwd=workspace,
        )

        commit_sha = result.stdout.strip().lower()

        if (
            result.returncode != 0
            or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit_sha)
        ):
            raise GitCheckoutError(
                "Could not determine the checked-out commit."
            )

        return GitCheckout(
            workspace=workspace,
            commit_sha=commit_sha,
        )

    except Exception:
        if workspace is not None:
            try:
                resolved = workspace.resolve()
                if resolved.is_relative_to(root) and resolved != root:
                    shutil.rmtree(resolved, ignore_errors=True)
            except OSError:
                pass
        raise


def cleanup_checkout(workspace: Path) -> None:
    """Remove a checkout only when it is inside the configured workspace root."""

    root = _workspace_root()
    resolved = workspace.resolve()

    if resolved == root or not resolved.is_relative_to(root):
        raise GitCheckoutError("Refusing to remove a path outside the workspace.")

    if resolved.is_symlink():
        raise GitCheckoutError("Refusing to remove a symbolic-link workspace.")

    shutil.rmtree(resolved, ignore_errors=False)
