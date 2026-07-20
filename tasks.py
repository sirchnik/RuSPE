# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from shutil import copy2, which

from invoke.context import Context

from collections.abc import Callable

from tools.build.invoke_support import (
    build_task,
    run_command,
    VscodeLaunchTarget,
    VscodeBuildTarget,
)
from boards.psc3m5_evk.secure.tasks import (
    vscode_build_targets as psc3_build_targets,
    vscode_launch_targets as psc3_launch_targets,
)
from boards.psc3m5_evk.tasks import SVD_INFO as psc3_svd
from boards.psc3m5_evk.secure_ipc.tasks import (
    vscode_build_targets as psc3_ipc_build_targets,
    vscode_launch_targets as psc3_ipc_launch_targets,
)
from boards.musca_b1.secure.tasks import (
    vscode_build_targets as musca_build_targets,
    vscode_launch_targets as musca_launch_targets,
)
from boards.musca_b1.tasks import SVD_INFO as musca_svd

all_build_targets: list[Callable[[bool], list[VscodeBuildTarget]]] = [
    psc3_build_targets,
    psc3_ipc_build_targets,
    musca_build_targets,
]
all_launch_targets: list[Callable[[bool], list[VscodeLaunchTarget]]] = [
    psc3_launch_targets,
    psc3_ipc_launch_targets,
    musca_launch_targets,
]

all_svds = [
    psc3_svd,
    musca_svd,
]


REPO_ROOT = Path(__file__).resolve().parent
VSCODE_DIR = REPO_ROOT / ".vscode"
LOCAL_DIR = REPO_ROOT / ".local"
SVD_DIR = LOCAL_DIR / "svds"
TASKS_JSON = VSCODE_DIR / "tasks.json"
LAUNCH_JSON = VSCODE_DIR / "launch.json"
SETTINGS_TEMPLATE_JSON = VSCODE_DIR / "settings.template.json"
SETTINGS_JSON = VSCODE_DIR / "settings.json"

TASKS_FILE_NAME = "tasks.py"

# Crates that only compile for the embedded target, not on the host.
_BIN_CRATES = [
    "psc3m5_evk_secure",
    "psc3m5_evk_secure_ipc",
    "psc3m5_evk_test_nspe",
    "psc3m5_evk_tock_kernel",
    "tock_psa_app",
    "psc3m5_evk_attest_srv",
    "psc3m5_evk_crypto_srv",
    "musca_b1_secure",
    "musca_b1_test_nspe",
    "shared_test_nspe",
    "tock_interrupt_test_app",
]


def _build_exclude_args(exclude_list: list[str]) -> str:
    return " ".join(f"--exclude {c}" for c in exclude_list)


def _build_task_directories() -> list[Path]:
    excluded_dirs = {".git", ".venv", "target", "tock-sub"}
    task_files = []
    for path in REPO_ROOT.rglob(TASKS_FILE_NAME):
        if path == REPO_ROOT / TASKS_FILE_NAME:
            continue
        if excluded_dirs.intersection(path.relative_to(REPO_ROOT).parts):
            continue
        try:
            content = path.read_text(encoding="utf-8")
            if "def build(" in content:
                task_files.append(path)
        except Exception:
            pass
    return [path.parent for path in sorted(task_files)]


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


def _tasks_targets(release: bool = False) -> list[VscodeBuildTarget]:
    targets: list[VscodeBuildTarget] = []
    for board_build_targets in all_build_targets:
        targets.extend(board_build_targets(release))
    return targets


def _tasks_conf(targets: list[VscodeBuildTarget]) -> dict[str, object]:
    return {"version": "2.0.0", "tasks": [t.to_dict() for t in targets]}


def _launch_targets(release: bool = False) -> list[VscodeLaunchTarget]:
    targets: list[VscodeLaunchTarget] = []
    for board_launch_targets in all_launch_targets:
        targets.extend(board_launch_targets(release))
    return targets


def _launch_conf(targets: list[VscodeLaunchTarget]) -> dict[str, object]:
    return {
        "version": "0.2.0",
        "configurations": [t.to_dict() for t in targets],
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

    for filename, url in all_svds:
        svd_path = SVD_DIR / filename
        if not svd_path.exists() or force:
            _download(url, svd_path)
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


@build_task(
    help={
        "mode": "Mode of tests to run: 'unit', 'integration', or 'all'.",
        "debug": "Build and use debug profile for system tests.",
    }
)
def test(ctx: Context, mode: str = "all", debug: bool = False):
    """Run tests."""
    if mode in ["unit", "all"]:
        print("Running unit tests...")
        run_command(f"cargo test --workspace {_build_exclude_args(_BIN_CRATES)}")

    if mode in ["integration", "all"]:
        print("Running integration tests...")
        cmd = [sys.executable, "tests/test_musca.py"]
        if debug:
            cmd.append("--debug")
        run_command(cmd)


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
    """Run rustfmt on all git-tracked files using run_command, ignoring the tock-sub folder."""
    result = run_command(
        ["git", "ls-files"],
        capture_output=True,
    )
    tracked_files = result.stdout.splitlines()

    rust_files = [
        f
        for f in tracked_files
        if f.endswith(".rs") and not f.startswith("integrations/tock/tock-sub/")
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
    cmd = "cspell lint --no-progress --show-suggestions -c cspell.config.yaml ."
    if which("pnpm"):
        run_command(f"pnpm dlx {cmd}")
    else:
        run_command(f"npx -y {cmd}")


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
