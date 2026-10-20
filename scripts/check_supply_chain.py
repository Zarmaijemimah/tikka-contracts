#!/usr/bin/env python3
"""CI check: block editor/package-manager code-execution vectors from entering the repo.

Guards the paths abused by the 2026 "auto-task" malware campaign that spread
through merged pull requests on GitHub: a font-shaped binary blob dropped under
a web asset directory, a loader at ``dist/setup.js``, and a VS Code task or an
npm lifecycle script wired to run it the moment the repo is opened or installed.

Usage:
    python scripts/check_supply_chain.py [--root PATH]

Only tracked files are inspected, so a local build directory never trips the
check. Lockfiles are read rather than installed, so the scan needs no network
and stays independent of whether a lockfile is currently in sync with its
manifest. Exits non-zero and prints one line per finding if anything matches.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Exact artefacts named in the campaign advisory. Matched on the full repo path.
KNOWN_BAD_PATHS = {
    "dist/setup.js",
    "public/fonts/fa-solid-500.woff2",
    "public/fonts/fa-solid-600.eot",
    "public/fonts/fa-solid-300.llf",
}

# The dropper disguises itself as a webfont. This repo ships Rust contracts and
# a Node oracle service — it has no legitimate reason to track font binaries.
FONT_SUFFIXES = {".woff", ".woff2", ".eot", ".ttf", ".otf", ".llf"}

# npm runs these without asking, so a malicious one executes on `npm install`.
# `prepare` also runs on `npm ci` and on `npm install` from a git dependency.
DANGEROUS_NPM_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")

# Dependencies that legitimately run an install script, with why. Both are
# native-binding packages that compile or fetch a prebuilt binary on install,
# and both are dev-only, reached through jest. A *new* entry appearing in the
# lockfile is the thing worth reviewing, so this is keyed by name only: routine
# version bumps stay quiet, a newly install-scripted package does not.
ALLOWED_INSTALL_SCRIPTS = {
    "node_modules/@parcel/watcher": "native file watcher, dev-only via jest-haste-map",
    "node_modules/unrs-resolver": "native resolver binding, dev-only via jest-resolve",
}

# VS Code auto-run surfaces: the setting that permits folder-open tasks, and the
# task property that marks a task as one. Either alone is enough to flag.
AUTOMATIC_TASK_SETTING = "task.allowAutomaticTasks"
FOLDER_OPEN_RUN_ON = re.compile(r'"runOn"\s*:\s*"folderOpen"')


def tracked_files(root: Path) -> list[str]:
    """Return every path git tracks at `root`, as repo-relative POSIX strings."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [path for path in result.stdout.split("\0") if path]


def check_known_bad_paths(paths: list[str]) -> list[str]:
    return [
        f"{path}: known malware artefact from the 2026 auto-task campaign"
        for path in paths
        if path in KNOWN_BAD_PATHS
    ]


def check_font_binaries(paths: list[str]) -> list[str]:
    return [
        f"{path}: tracked font binary — the campaign dropper ships as a webfont; "
        f"this repo tracks no fonts"
        for path in paths
        if Path(path).suffix.lower() in FONT_SUFFIXES
    ]


def check_symlinks(root: Path, paths: list[str]) -> list[str]:
    """Flag tracked symlinks that resolve outside the repository."""
    findings = []
    for path in paths:
        full = root / path
        if not full.is_symlink():
            continue
        target = (full.parent / full.readlink()).resolve()
        if not target.is_relative_to(root.resolve()):
            findings.append(f"{path}: tracked symlink escapes the repository -> {target}")
    return findings


def check_npm_scripts(root: Path, paths: list[str]) -> list[str]:
    """Flag install-time lifecycle scripts in any tracked package.json."""
    findings = []
    for path in paths:
        if Path(path).name != "package.json":
            continue
        try:
            manifest = json.loads((root / path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(f"{path}: could not be parsed as JSON ({exc})")
            continue
        scripts = manifest.get("scripts")
        if not isinstance(scripts, dict):
            continue
        findings.extend(
            f"{path}: '{name}' lifecycle script runs automatically on install -> {scripts[name]!r}"
            for name in DANGEROUS_NPM_SCRIPTS
            if name in scripts
        )
    return findings


def check_lockfile_install_scripts(root: Path, paths: list[str]) -> list[str]:
    """Flag locked dependencies that npm would run an install script for.

    npm records this as ``hasInstallScript`` when it resolves the tree, so the
    lockfile alone answers the question — no install, and no dependence on the
    lockfile being in sync with its manifest.
    """
    findings = []
    for path in paths:
        if Path(path).name != "package-lock.json":
            continue
        try:
            lockfile = json.loads((root / path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(f"{path}: could not be parsed as JSON ({exc})")
            continue
        packages = lockfile.get("packages")
        if not isinstance(packages, dict):
            continue
        for name, entry in sorted(packages.items()):
            if not isinstance(entry, dict) or not entry.get("hasInstallScript"):
                continue
            if name not in ALLOWED_INSTALL_SCRIPTS:
                findings.append(
                    f"{path}: dependency {name or '<root>'} runs an install script "
                    f"({entry.get('version', 'unknown version')}) — review it before "
                    f"this lockfile change lands"
                )
    return findings


def check_vscode_settings(root: Path, paths: list[str]) -> list[str]:
    """Flag VS Code settings that re-enable tasks running on folder open."""
    findings = []
    for path in paths:
        if not path.endswith(".vscode/settings.json") and path != ".vscode/settings.json":
            continue
        text = (root / path).read_text(encoding="utf-8")
        if AUTOMATIC_TASK_SETTING not in text:
            continue
        # The supported values are "on"/"off"; the campaign wrote a bare `true`.
        # Anything that is not an explicit "off" re-opens the hole.
        match = re.search(rf'"{re.escape(AUTOMATIC_TASK_SETTING)}"\s*:\s*("?[A-Za-z]+"?)', text)
        value = match.group(1) if match else "<unparsed>"
        if value != '"off"':
            findings.append(
                f"{path}: {AUTOMATIC_TASK_SETTING} is {value} — tasks would run on "
                f'folder open; set it to "off"'
            )
    return findings


def check_vscode_tasks(root: Path, paths: list[str]) -> list[str]:
    """Flag tasks declared to run on folder open."""
    return [
        f'{path}: declares a task with "runOn": "folderOpen" — it executes '
        f"without user action when the repo is opened"
        for path in paths
        if Path(path).name == "tasks.json"
        and FOLDER_OPEN_RUN_ON.search((root / path).read_text(encoding="utf-8"))
    ]


def run_checks(root: Path) -> list[str]:
    paths = tracked_files(root)
    return [
        *check_known_bad_paths(paths),
        *check_font_binaries(paths),
        *check_symlinks(root, paths),
        *check_npm_scripts(root, paths),
        *check_lockfile_install_scripts(root, paths),
        *check_vscode_settings(root, paths),
        *check_vscode_tasks(root, paths),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root to scan (defaults to this script's repository).",
    )
    args = parser.parse_args()

    findings = run_checks(args.root)
    if findings:
        print("Supply-chain guard found code-execution vectors:\n")
        for finding in findings:
            print(f"  ERROR: {finding}")
        print(
            "\nIf a finding is a deliberate, reviewed change, update "
            "scripts/check_supply_chain.py in the same pull request so the "
            "exception is reviewed alongside it."
        )
        return 1

    print("Supply-chain guard: no editor or install-time execution vectors found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
