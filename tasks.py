# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from shutil import copy2

from invoke.context import Context

from tools.build.invoke_support import (
    resolve_openocd,
    build_task,
    run_command,
    VscodeLaunchTarget,
    VscodeBuildTarget,
)
from boards.psc3m5_evk.secure.tasks import (
    vscode_build_targets as secure_build_targets,
    vscode_launch_targets as secure_launch_targets,
)
from boards.psc3m5_evk.secure_ipc.tasks import (
    vscode_build_targets as secure_ipc_build_targets,
    vscode_launch_targets as secure_ipc_launch_targets,
)


REPO_ROOT = Path(__file__).resolve().parent
VSCODE_DIR = REPO_ROOT / ".vscode"
LOCAL_DIR = REPO_ROOT / ".local"
SVD_DIR = LOCAL_DIR / "svds"
PSC3_SVD = SVD_DIR / "psc3.svd"
TASKS_JSON = VSCODE_DIR / "tasks.json"
LAUNCH_JSON = VSCODE_DIR / "launch.json"
SETTINGS_TEMPLATE_JSON = VSCODE_DIR / "settings.template.json"
SETTINGS_JSON = VSCODE_DIR / "settings.json"

PSC3_SVD_URL = "https://raw.githubusercontent.com/Infineon/mtb-pdl-cat1/refs/heads/master/devices/COMPONENT_CAT1B/svd/psc3.svd"
TASKS_FILE_NAME = "tasks.py"

# Crates that only compile for the embedded target, not on the host.
_BIN_CRATES = [
    "psc3m5_evk_secure",
    "psc3m5_evk_secure_ipc",
    "psc3m5_evk_test_nspe",
    "psc3m5_evk_tock_kernel",
    "psc3m5_evk_tock_app",
    "psc3m5_evk_attest_srv",
    "psc3m5_evk_crypto_srv",
]


def _build_exclude_args(exclude_list: list[str]) -> str:
    return " ".join(f"--exclude {c}" for c in exclude_list)


def _build_task_directories() -> list[Path]:
    excluded_dirs = {".git", ".venv", "target"}
    task_files = sorted(
        path
        for path in REPO_ROOT.rglob(TASKS_FILE_NAME)
        if path != REPO_ROOT / TASKS_FILE_NAME
        and path.relative_to(REPO_ROOT).parts[0] != "tock"
        and not excluded_dirs.intersection(path.relative_to(REPO_ROOT).parts)
    )
    return [path.parent for path in task_files]


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


def _tasks_targets(release: bool = False) -> list[VscodeBuildTarget]:
    targets: list[VscodeBuildTarget] = []
    targets.extend(secure_build_targets(release))
    targets.extend(secure_ipc_build_targets(release))
    return targets


def _tasks_conf(targets: list[VscodeBuildTarget]) -> dict[str, object]:
    return {"version": "2.0.0", "tasks": targets}


def _launch_targets(release: bool = False) -> list[VscodeLaunchTarget]:
    openocd_path = str(resolve_openocd(version="infineon"))
    
    targets: list[VscodeLaunchTarget] = []
    targets.extend(secure_launch_targets(openocd_path, release))
    targets.extend(secure_ipc_launch_targets(openocd_path, release))
    return targets


def _launch_conf(targets: list[VscodeLaunchTarget]) -> dict[str, object]:
    return {
        "version": "0.2.0",
        "configurations": targets,
    }


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response:
        destination.write_bytes(response.read())


@build_task(default=True)
def vscode(ctx: Context, force=False, release_debug_config=False):
    """Set up the VS Code workspace files."""

    if not (REPO_ROOT / ".venv").exists():
        raise FileNotFoundError(
            f"Missing virtual environment. Please run 'python -m venv .venv' in {REPO_ROOT} and install the required dependencies."
        )

    if not SETTINGS_JSON.exists() or force:
        if not SETTINGS_TEMPLATE_JSON.exists():
            raise FileNotFoundError(
                f"Missing settings template: {SETTINGS_TEMPLATE_JSON}"
            )
        copy2(SETTINGS_TEMPLATE_JSON, SETTINGS_JSON)

    if not PSC3_SVD.exists() or force:
        _download(PSC3_SVD_URL, PSC3_SVD)
    _write_json(
        TASKS_JSON,
        _tasks_conf(_tasks_targets())
        if not release_debug_config
        else _tasks_conf(_tasks_targets(True) + _tasks_targets(False)),
    )
    _write_json(
        LAUNCH_JSON,
        _launch_conf(_launch_targets())
        if not release_debug_config
        else _launch_conf(_launch_targets(True) + _launch_targets(False)),
    )


@build_task
def install(ctx):
    """Install the Rust toolchain and all required external tools."""
    run_command(["cargo", "install", "cargo-binutils", "--locked"])
    run_command(["cargo", "install", "cargo-llvm-cov", "--locked"])
    run_command(["cargo", "install", "elf2tab", "--locked"])


@build_task
def build(ctx: Context, debug=False):
    """Run `inv build` for every nested Invoke task file in the repository."""

    build_dirs = _build_task_directories()
    if not build_dirs:
        raise FileNotFoundError(
            f"No nested {TASKS_FILE_NAME} files found under {REPO_ROOT}"
        )

    debug_arg = " --debug" if debug else ""
    for build_dir in build_dirs:
        relative_dir = build_dir.relative_to(REPO_ROOT)
        print(f"Building {relative_dir}")
        run_command(f"{sys.executable} -m invoke build{debug_arg}", cwd=str(build_dir))


@build_task
def clippy(ctx):
    """Run cargo clippy on all host-compilable crates."""
    run_command(
        f"cargo clippy --workspace {_build_exclude_args(_BIN_CRATES)} -- -D warnings"
    )


@build_task
def test(ctx):
    """Run cargo test on all host-compilable crates."""
    run_command(f"cargo test --workspace {_build_exclude_args(_BIN_CRATES)}")


@build_task
def miri(ctx):
    """Run cargo miri test on all host-compilable crates."""
    run_command(f"cargo miri test --workspace {_build_exclude_args(_BIN_CRATES)}")


@build_task
def coverage(ctx: Context, html=False):
    """Run tests with coverage via cargo-llvm-cov. Pass --html for an HTML report."""
    if html:
        run_command(
            f"cargo llvm-cov --workspace {_build_exclude_args(_BIN_CRATES)} --html"
        )
    else:
        run_command(
            f"cargo llvm-cov --workspace {_build_exclude_args(_BIN_CRATES)} --lcov --output-path target/llvm-cov/lcov.info",
        )


@build_task
def fmt(ctx: Context, check=False):
    """Run rustfmt on all git-tracked files using run_command, ignoring the tock folder."""
    result = run_command(
        ["git", "ls-files"],
        capture_output=True,
    )
    tracked_files = result.stdout.splitlines()

    rust_files = [
        f for f in tracked_files if f.endswith(".rs") and not f.startswith("tock/")
    ]

    if not rust_files:
        print("No Rust files found to format.")
        return

    cmd = ["rustfmt", "--edition", "2024"]
    if check:
        cmd.append("--check")
    cmd.extend(rust_files)

    run_command(cmd, shorten_args=True)


@build_task
def check_spelling(ctx: Context):
    """Run cspell"""
    run_command(
        "npx -y cspell lint --no-progress --show-suggestions -c cspell.config.yaml ."
    )


@build_task
def reuse(ctx: Context):
    """Run reuse linting"""
    run_command("python -m reuse lint")


@build_task
def reuse_annotate(ctx: Context, comment: str):
    """Run reuse annotate to add missing SPDX headers"""
    run_command(
        f'python -m reuse annotate -l MIT -c "{comment}" --recursive . --skip-unrecognised --exclude-year --skip-existing'
    )


@build_task
def ci(ctx):
    """Run the main CI checks: fmt --check, clippy, build, test, miri."""
    fmt(ctx, check=True)
    check_spelling(ctx)
    clippy(ctx)
    build(ctx)
    test(ctx)
    miri(ctx)
