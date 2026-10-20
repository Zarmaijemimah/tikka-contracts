"""Unit tests for scripts/check_supply_chain.py.

Each check is exercised against a throwaway git repository so the suite proves
the guard fires on the real campaign artefacts and stays quiet on the shapes
this repo legitimately contains.

Edge cases exercised:
  - Clean tree: no findings
  - Known artefact paths: dist/setup.js and the fa-solid font blobs
  - Font binary tracked under any path
  - npm lifecycle scripts (preinstall/install/postinstall/prepare)
  - package.json with no scripts block, and with a malformed body
  - lockfile dependencies with install scripts, allowlisted and not
  - task.allowAutomaticTasks set to true / "on" / "off"
  - tasks.json declaring runOn: folderOpen
  - symlinks pointing inside vs. outside the repository
  - untracked files are ignored
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Make the scripts package importable without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check_supply_chain import (
    ALLOWED_INSTALL_SCRIPTS,
    check_font_binaries,
    check_known_bad_paths,
    check_lockfile_install_scripts,
    check_npm_scripts,
    check_symlinks,
    check_vscode_settings,
    check_vscode_tasks,
    run_checks,
    tracked_files,
)


def write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A git repository containing only the files a test adds and commits."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def track(root: Path) -> None:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)


# --- known artefacts -------------------------------------------------------


def test_known_bad_paths_flags_each_campaign_artefact() -> None:
    paths = [
        "dist/setup.js",
        "public/fonts/fa-solid-500.woff2",
        "public/fonts/fa-solid-600.eot",
        "public/fonts/fa-solid-300.llf",
    ]
    assert len(check_known_bad_paths(paths)) == 4


def test_known_bad_paths_ignores_similar_names() -> None:
    # A setup.js that is not the dist/ dropper is left to other checks.
    assert check_known_bad_paths(["oracle/test/setup.js", "src/dist/setup.js"]) == []


# --- font binaries ---------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["public/fonts/fa-solid-500.woff2", "assets/x.EOT", "a/b/c.llf", "f.ttf"],
)
def test_font_binaries_flagged_anywhere(path: str) -> None:
    assert len(check_font_binaries([path])) == 1


def test_font_binaries_ignores_source_files() -> None:
    assert check_font_binaries(["src/index.ts", "fonts.css", "README.md"]) == []


# --- npm lifecycle scripts -------------------------------------------------


@pytest.mark.parametrize("name", ["preinstall", "install", "postinstall", "prepare"])
def test_npm_lifecycle_scripts_flagged(repo: Path, name: str) -> None:
    write(repo, "package.json", f'{{"scripts": {{"{name}": "node dist/setup.js"}}}}')
    findings = check_npm_scripts(repo, ["package.json"])
    assert len(findings) == 1
    assert name in findings[0]


def test_npm_safe_scripts_not_flagged(repo: Path) -> None:
    write(repo, "oracle/package.json", '{"scripts": {"build": "tsc", "test": "jest"}}')
    assert check_npm_scripts(repo, ["oracle/package.json"]) == []


def test_npm_manifest_without_scripts_not_flagged(repo: Path) -> None:
    write(repo, "package.json", '{"name": "x", "version": "1.0.0"}')
    assert check_npm_scripts(repo, ["package.json"]) == []


def test_npm_malformed_manifest_reported(repo: Path) -> None:
    write(repo, "package.json", "{not json")
    findings = check_npm_scripts(repo, ["package.json"])
    assert len(findings) == 1
    assert "could not be parsed" in findings[0]


# --- lockfile install scripts ----------------------------------------------


def test_lockfile_install_script_flagged(repo: Path) -> None:
    write(
        repo,
        "package-lock.json",
        '{"packages": {"node_modules/evil": {"version": "1.0.0", "hasInstallScript": true}}}',
    )
    findings = check_lockfile_install_scripts(repo, ["package-lock.json"])
    assert len(findings) == 1
    assert "node_modules/evil" in findings[0]


def test_lockfile_allowlisted_install_script_not_flagged(repo: Path) -> None:
    allowed = next(iter(ALLOWED_INSTALL_SCRIPTS))
    write(
        repo,
        "package-lock.json",
        f'{{"packages": {{"{allowed}": {{"version": "9.9.9", "hasInstallScript": true}}}}}}',
    )
    assert check_lockfile_install_scripts(repo, ["package-lock.json"]) == []


def test_lockfile_without_install_scripts_not_flagged(repo: Path) -> None:
    write(
        repo,
        "package-lock.json",
        '{"packages": {"node_modules/fine": {"version": "1.0.0"}}}',
    )
    assert check_lockfile_install_scripts(repo, ["package-lock.json"]) == []


def test_lockfile_malformed_reported(repo: Path) -> None:
    write(repo, "package-lock.json", "{not json")
    findings = check_lockfile_install_scripts(repo, ["package-lock.json"])
    assert len(findings) == 1
    assert "could not be parsed" in findings[0]


# --- VS Code settings and tasks --------------------------------------------


@pytest.mark.parametrize("value", ["true", '"on"', '"always"'])
def test_automatic_tasks_enabled_flagged(repo: Path, value: str) -> None:
    write(repo, ".vscode/settings.json", f'{{"task.allowAutomaticTasks": {value}}}')
    assert len(check_vscode_settings(repo, [".vscode/settings.json"])) == 1


def test_automatic_tasks_explicitly_off_not_flagged(repo: Path) -> None:
    write(repo, ".vscode/settings.json", '{"task.allowAutomaticTasks": "off"}')
    assert check_vscode_settings(repo, [".vscode/settings.json"]) == []


def test_settings_without_the_key_not_flagged(repo: Path) -> None:
    write(repo, ".vscode/settings.json", '{"editor.formatOnSave": true}')
    assert check_vscode_settings(repo, [".vscode/settings.json"]) == []


def test_folder_open_task_flagged(repo: Path) -> None:
    write(
        repo,
        ".vscode/tasks.json",
        '{"tasks": [{"label": "eslint-check", "runOptions": {"runOn": "folderOpen"}}]}',
    )
    assert len(check_vscode_tasks(repo, [".vscode/tasks.json"])) == 1


def test_manual_task_not_flagged(repo: Path) -> None:
    write(repo, ".vscode/tasks.json", '{"tasks": [{"label": "build", "type": "shell"}]}')
    assert check_vscode_tasks(repo, [".vscode/tasks.json"]) == []


# --- symlinks --------------------------------------------------------------


def test_symlink_inside_repo_not_flagged(repo: Path) -> None:
    (repo / "real").mkdir()
    (repo / "link").symlink_to("real")
    assert check_symlinks(repo, ["link"]) == []


def test_symlink_escaping_repo_flagged(repo: Path) -> None:
    (repo / "link").symlink_to("../outside")
    findings = check_symlinks(repo, ["link"])
    assert len(findings) == 1
    assert "escapes the repository" in findings[0]


# --- end to end ------------------------------------------------------------


def test_clean_repository_has_no_findings(repo: Path) -> None:
    write(repo, "README.md", "# ok\n")
    write(repo, "oracle/package.json", '{"scripts": {"build": "tsc"}}')
    track(repo)
    assert run_checks(repo) == []


def test_campaign_payload_is_caught_end_to_end(repo: Path) -> None:
    write(repo, "dist/setup.js", "// dropper\n")
    write(repo, "public/fonts/fa-solid-500.woff2", "binary-ish")
    write(repo, "package.json", '{"scripts": {"preinstall": "node dist/setup.js"}}')
    write(repo, ".vscode/settings.json", '{"task.allowAutomaticTasks": true}')
    write(
        repo,
        ".vscode/tasks.json",
        '{"tasks": [{"label": "eslint-check", "runOptions": {"runOn": "folderOpen"}}]}',
    )
    track(repo)
    findings = run_checks(repo)
    # Two known paths, one font, one lifecycle script, one setting, one task.
    assert len(findings) == 6


def test_untracked_files_are_ignored(repo: Path) -> None:
    write(repo, "README.md", "# ok\n")
    track(repo)
    write(repo, "dist/setup.js", "// not committed\n")
    assert "dist/setup.js" not in tracked_files(repo)
    assert run_checks(repo) == []
