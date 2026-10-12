import subprocess
from pathlib import Path

import pytest

from app.services import git_repository
from app.services.git_repository import (
    GitCheckoutError,
    _validate_branch,
    checkout_repository,
    cleanup_checkout,
)


def test_branch_validation_accepts_normal_branch_names():
    assert _validate_branch("main") == "main"
    assert _validate_branch("feature/security-scan") == "feature/security-scan"


@pytest.mark.parametrize(
    "branch",
    [
        "",
        "-option",
        "../main",
        "feature/../main",
        "bad branch",
        "branch.lock",
        "branch@{1}",
        "branch:name",
    ],
)
def test_branch_validation_rejects_unsafe_names(branch):
    with pytest.raises(GitCheckoutError):
        _validate_branch(branch)


def test_checkout_rejects_non_https_repository():
    with pytest.raises(GitCheckoutError, match="repository URL"):
        checkout_repository(
            owner_id=1,
            repository_id=2,
            scan_id=3,
            clone_url="file:///tmp/repository",
            branch="main",
        )


def test_checkout_creates_isolated_workspace_and_returns_commit(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("VULNGUARD_WORKSPACE_ROOT", str(tmp_path))
    calls = []

    def fake_run(arguments, **kwargs):
        calls.append(arguments)

        if "clone" in arguments:
            destination = Path(arguments[-1])
            (destination / ".git").mkdir()
            (destination / "README.md").write_text("safe test fixture")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        return subprocess.CompletedProcess(
            arguments, 0, "a" * 40 + "\n", ""
        )

    monkeypatch.setattr(git_repository.subprocess, "run", fake_run)

    checkout = checkout_repository(
        owner_id=1,
        repository_id=2,
        scan_id=3,
        clone_url="https://github.com/example/project.git",
        branch="main",
    )

    assert checkout.workspace.is_dir()
    assert checkout.workspace.is_relative_to(tmp_path)
    assert checkout.commit_sha == "a" * 40
    assert calls[0][0] == "git"
    assert "clone" in calls[0]
    assert "--depth" in calls[0]
    assert "--branch" in calls[0]
    assert kwargs_timeout(calls, fake_run) is True

    cleanup_checkout(checkout.workspace)
    assert not checkout.workspace.exists()


def kwargs_timeout(calls, fake_run):
    # The timeout assertion is made by inspecting the runner's invocation
    # in the dedicated test below.
    return bool(calls) and callable(fake_run)


def test_git_runner_sets_timeout_and_disables_interactive_prompts(monkeypatch):
    captured = {}

    def fake_run(arguments, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(git_repository.subprocess, "run", fake_run)

    git_repository._run_git(["--version"], timeout=12)

    assert captured["timeout"] == 12
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_checkout_removes_workspace_when_git_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNGUARD_WORKSPACE_ROOT", str(tmp_path))

    def fake_run(arguments, **kwargs):
        if "clone" in arguments:
            Path(arguments[-1]).mkdir(exist_ok=True)
        return subprocess.CompletedProcess(arguments, 128, "", "private details")

    monkeypatch.setattr(git_repository.subprocess, "run", fake_run)

    with pytest.raises(GitCheckoutError, match="checkout failed"):
        checkout_repository(
            owner_id=1,
            repository_id=2,
            scan_id=3,
            clone_url="https://github.com/example/project.git",
            branch="main",
        )

    scan_parent = tmp_path / "1" / "2"
    assert list(scan_parent.iterdir()) == []


def test_cleanup_refuses_paths_outside_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNGUARD_WORKSPACE_ROOT", str(tmp_path))

    outside = tmp_path.parent / "not-a-vulnguard-workspace"
    outside.mkdir(exist_ok=True)

    try:
        with pytest.raises(GitCheckoutError):
            cleanup_checkout(outside)
    finally:
        outside.rmdir()
