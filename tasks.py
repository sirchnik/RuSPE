from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from shutil import copy2

from invoke.tasks import task


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

# Crates that only compile for the embedded target, not on the host.
_EMBEDDED_ONLY_CRATES = [
    "psc3m5_evk_secure",
    "psc3m5_evk_test",
    "psc3m5_evk_tock",
    "psa_tock_app",
]

_EXCLUDE_ARGS = " ".join(f"--exclude {c}" for c in _EMBEDDED_ONLY_CRATES)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


def _inv_executable() -> str:
    if os.name == "nt":
        return "${workspaceFolder}\\.venv\\Scripts\\inv.exe"
    return "${workspaceFolder}/.venv/bin/inv"


def _tasks_payload() -> dict[str, object]:
    inv_executable = _inv_executable()
    if os.name == "nt":
        build_command = f'& "{inv_executable}" build --debug'
        build_with_app_command = f'$app = \'${{config:tock.app}}\'; if ($app) {{ & "{inv_executable}" build --debug --app "$app" }} else {{ & "{inv_executable}" build --debug }}'
    else:
        build_command = f'"{inv_executable}" build --debug'
        build_with_app_command = (
            "app='${config:tock.app}'; "
            f'if [ -n "$app" ]; then "{inv_executable}" build --debug --app "$app"; '
            f'else "{inv_executable}" build --debug; fi'
        )

    return {
        "version": "2.0.0",
        "tasks": [
            {
                "label": "build.psc3m5_evk_test",
                "command": build_command,
                "type": "shell",
                "args": [],
                "options": {"cwd": "${workspaceFolder}/boards/psc3m5_evk_test"},
                "presentation": {"reveal": "silent"},
                "group": "build",
            },
            {
                "label": "build.psc3m5_evk_tock",
                "command": build_with_app_command,
                "type": "shell",
                "args": [],
                "options": {"cwd": "${workspaceFolder}/boards/tock/psc3m5_evk_tock"},
                "presentation": {"reveal": "silent"},
                "group": "build",
            },
        ],
    }


def _launch_payload() -> dict[str, object]:
    psc3m5_base_conf = {
        "type": "cortex-debug",
        "servertype": "openocd",
        "request": "launch",
        "cwd": "${workspaceFolder}",
        "openOCDLaunchCommands": ["init; reset init;"],
        "overrideRestartCommands": ["starti"],
        "svdFile": "${workspaceFolder}/.local/svds/psc3.svd",
        "configFiles": ["${workspaceFolder}/boards/psc3m5_evk_test/openocd.tcl"],
    }
    return {
        "version": "0.2.0",
        "configurations": [
            {
                **psc3m5_base_conf,
                "name": "PSC3-Test",
                "executable": "target/thumbv8m.main-none-eabi/debug/psc3m5_evk_test_merged.hex",
                "preLaunchCommands": [
                    "add-symbol-file target/thumbv8m.main-none-eabi/debug/psc3m5_evk_test",
                    "add-symbol-file target/thumbv8m.main-none-eabi/debug/psc3m5_evk_secure",
                ],
                "preLaunchTask": "build.psc3m5_evk_test",
            },
            {
                **psc3m5_base_conf,
                "name": "PSC3-Tock",
                "executable": "target/thumbv8m.main-none-eabi/debug/psc3m5_evk_tock_merged.hex",
                "preLaunchCommands": [
                    "add-symbol-file target/thumbv8m.main-none-eabi/debug/psc3m5_evk_tock",
                    "add-symbol-file target/thumbv8m.main-none-eabi/debug/psc3m5_evk_secure",
                ],
                "preLaunchTask": "build.psc3m5_evk_tock",
            },
        ],
    }


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response:
        destination.write_bytes(response.read())


@task(default=True)
def vscode(ctx, force=False):
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

    _write_json(TASKS_JSON, _tasks_payload())
    _write_json(LAUNCH_JSON, _launch_payload())


@task
def install(ctx):
    """Install the Rust toolchain and all required external tools."""
    ctx.run("cargo install cargo-binutils --locked")
    ctx.run("cargo install cargo-llvm-cov --locked")
    ctx.run("cargo install elf2tab --locked")


@task
def clippy(ctx):
    """Run cargo clippy on all host-compilable crates."""
    ctx.run(f"cargo clippy --workspace {_EXCLUDE_ARGS} -- -D warnings")


@task
def test(ctx):
    """Run cargo test on all host-compilable crates."""
    ctx.run(f"cargo test --workspace {_EXCLUDE_ARGS}")


@task
def miri(ctx):
    """Run cargo miri test on all host-compilable crates."""
    ctx.run(f"cargo miri test --workspace {_EXCLUDE_ARGS}")


@task
def coverage(ctx, html=False):
    """Run tests with coverage via cargo-llvm-cov. Pass --html for an HTML report."""
    if html:
        ctx.run(f"cargo llvm-cov --workspace {_EXCLUDE_ARGS} --html")
    else:
        ctx.run(
            f"cargo llvm-cov --workspace {_EXCLUDE_ARGS} --lcov --output-path target/llvm-cov/lcov.info"
        )


@task
def fmt(ctx, check=False):
    """Run cargo fmt. Pass --check to verify formatting without changes."""
    check_flag = "--check" if check else ""
    ctx.run(f"cargo fmt --all {check_flag}".strip())


@task
def ci(ctx):
    """Run all CI checks: fmt --check, clippy, test, miri."""
    fmt(ctx, check=True)
    clippy(ctx)
    test(ctx)
    miri(ctx)
