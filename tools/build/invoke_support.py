# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import subprocess
import sys
from functools import wraps
from pathlib import Path
from shutil import which

from typing import Any
from dataclasses import dataclass, asdict

from invoke.context import Context
from invoke.exceptions import Exit
from invoke.tasks import task

@dataclass
class VscodeLaunchTarget:
    name: str | None = None
    type: str | None = None
    request: str | None = None
    cwd: str | None = None
    executable: str | None = None
    servertype: str | None = None
    serverpath: str | None = None
    openOCDLaunchCommands: list[str] | None = None
    svdFile: str | None = None
    configFiles: list[str] | None = None
    preLaunchCommands: list[str] | None = None
    preLaunchTask: str | None = None
    cpu: str | None = None
    machine: str | None = None
    serverArgs: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class VscodeBuildTarget:
    type: str | None = None
    args: list[str] | None = None
    presentation: dict[str, object] | None = None
    group: str | None = None
    label: str | None = None
    options: dict[str, object] | None = None
    command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}



def inv_executable() -> str:
    if os.name == "nt":
        return "${workspaceFolder}\\.venv\\Scripts\\inv.exe"
    return "${workspaceFolder}/.venv/bin/inv"


def vscode_common_build_task() -> VscodeBuildTarget:
    return VscodeBuildTarget(
        type="shell",
        args=[],
        presentation={"reveal": "silent"},
        group="build",
    )


def get_vscode_build_commands(release: bool = False) -> tuple[str, str]:
    """Return (test_cmd, tock_cmd) build commands — kept for backwards compat."""
    return (
        make_vscode_build_command(release, nspe="test"),
        make_vscode_build_command(release, nspe="tock"),
    )


def make_vscode_build_command(
    release: bool, nspe: str, features: str | None = None
) -> str:
    """Generate a VSCode shell command string for ``inv build --nspe=...``."""
    inv_exec = inv_executable()
    debug_arg = "" if release else " --debug"
    extra = f" --features={features}" if features else ""
    cmd = f'"{inv_exec}" build{debug_arg} --nspe={nspe}{extra}'
    if os.name == "nt":
        cmd = "& " + cmd
    return cmd


class BuildError(RuntimeError):
    """Raised when a build step cannot be completed."""


def handle_build_errors(func):
    """Decorator that catches BuildError and exits with a clean message."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BuildError as exc:
            print(f"\nerror: {exc}", file=sys.stderr)
            raise Exit(code=1) from None

    return wrapper


def build_task(_func=None, **task_kwargs):
    """Combine @task and @handle_build_errors into a single decorator."""

    def decorator(func):
        return task(**task_kwargs)(handle_build_errors(func))

    if _func is not None:
        return task(**task_kwargs)(handle_build_errors(_func))
    return decorator


def parse_features(features: str | None) -> list[str] | None:
    """Parse a comma-separated features string into a list, or None."""
    return [f.strip() for f in features.split(",")] if features else None


def _format_command(command: list[str], shorten_args: bool = True) -> str:
    # If shortening is disabled, just format everything normally.
    if not shorten_args:
        return subprocess.list2cmdline(command)

    # Find the last argument starting with '-'
    last_flag_idx = -1
    for idx, arg in enumerate(command):
        if arg.startswith("-"):
            last_flag_idx = idx

    if last_flag_idx != -1:
        if len(command) - (last_flag_idx + 1) > 1:
            start_pos_idx = last_flag_idx + 2
        else:
            start_pos_idx = last_flag_idx + 1
    else:
        start_pos_idx = 1

    trailing_args = command[start_pos_idx:]
    if len(trailing_args) > 5:
        kept_args = trailing_args[:5]
        contracted_cmd = command[:start_pos_idx] + kept_args
        cmd_text = subprocess.list2cmdline(contracted_cmd)
        cmd_text += f"...({len(trailing_args)})"
        return cmd_text
    else:
        return subprocess.list2cmdline(command)


def print_step(message: str):
    reset = "\x1b[0m"
    grey = "\x1b[90m"
    print(f"{grey}{message}{reset}")


def _merge_env(extra_env: dict[str, str] | None) -> dict[str, str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return env


def run_command(
    command: list[str] | str,
    *,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    in_stream: bool | None = None,
    verbose: bool | None = None,
    capture_output: bool = False,
    shorten_args: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command using subprocess (no Invoke context required).

    - `command` may be a list (preferred) or a shell string.
    - `cwd` may be a Path or string. If None current cwd is used.
    - `in_stream=False` will disable stdin (use DEVNULL).
    - `RUN_HANDLER_VERBOSE=0` in env disables the compact printout.
    - `capture_output=True` captures stdout/stderr as strings in the returned object.
    - `shorten_args=False` disables command argument contraction when printing.
    """
    # determine verbosity
    RUN_HANDLER_VERBOSE = os.environ.get("RUN_HANDLER_VERBOSE", "1") != "0"
    if verbose is None:
        verbose = RUN_HANDLER_VERBOSE

    def _is_sandbox() -> bool:
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
            return True
        try:
            return not sys.stdin.isatty()
        except Exception:
            return True

    merged_env = _merge_env(env)
    cmd_text = (
        command
        if isinstance(command, str)
        else _format_command(command, shorten_args=shorten_args)
    )

    if in_stream is None:
        in_stream = not _is_sandbox()

    if verbose:
        envs = ""
        if env:
            items = [f"{k}={v}" for k, v in list(env.items())]
            if shorten_args:
                envs = (" ".join(items) + ("..." if len(env) > 4 else "")) + " "
            else:
                envs = " ".join(items) + " "
        compact = f"$ cd {cwd or Path.cwd()} && {envs}{cmd_text}"
        print_step(compact)

    stdin = None if in_stream else subprocess.DEVNULL

    kwargs: dict[str, Any] = {
        "cwd": str(cwd) if cwd is not None else None,
        "env": merged_env,
        "check": True,
        "stdin": stdin,
    }
    if capture_output:
        kwargs["capture_output"] = True
        kwargs["text"] = True

    try:
        if isinstance(command, str):
            return subprocess.run(
                command,
                shell=True,
                **kwargs,
            )
        else:
            return subprocess.run(
                command,
                **kwargs,
            )
    except subprocess.CalledProcessError as error:
        raise BuildError(
            f"Command failed with exit code {error.returncode}: {cmd_text}"
        ) from error


def resolve_cmd(command_name: str) -> Path | None:
    add_paths = [str(Path.home() / ".cargo" / "bin")]
    path = path = (os.environ.get("PATH") or "") + ":" + (":".join(add_paths))
    resolved = which(command_name, path=path)
    return Path(resolved) if resolved else None


def _is_infineon_openocd(openocd_bin: Path) -> bool:
    """Check if the given OpenOCD binary is an Infineon version."""
    if "ModusToolbox" in str(openocd_bin):
        return True
    search_bases = [
        openocd_bin.parent,
        openocd_bin.parent.parent,
        openocd_bin.parent.parent.parent,
    ]
    targets = [
        Path("scripts") / "target" / "infineon" / "psc3.cfg",
    ]
    for base in search_bases:
        if not base:
            continue
        for t in targets:
            if (base / t).exists():
                return True
    return False


def resolve_openocd(version="default") -> Path | None:
    candidates: list[Path] = []
    openocd_root = os.environ.get("OPENOCD_ROOT")
    if openocd_root:
        root_path = Path(openocd_root)
        candidates.extend(
            (root_path / "bin" / "openocd.exe", root_path / "bin" / "openocd")
        )

    path_candidate = resolve_cmd("openocd")
    if path_candidate is not None:
        candidates.append(path_candidate)

    for candidate in candidates:
        if version == "infineon":
            if _is_infineon_openocd(candidate):
                return candidate
        elif candidate.exists():
            return candidate
    raise BuildError("OpenOCD was not found. Set OPENOCD_ROOT or add openocd to PATH.")


def _rust_sysroot_objcopy_candidates(ctx: Context) -> list[Path]:
    rustc = resolve_cmd("rustc")
    if rustc is None:
        return []

    try:
        completed = subprocess.run(
            [str(rustc), "--print", "sysroot"],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            return []
        sysroot = completed.stdout.strip()
    except Exception:
        return []

    if not sysroot:
        return []

    rustlib_dir = Path(sysroot) / "lib" / "rustlib"
    if not rustlib_dir.exists():
        return []

    candidates: list[Path] = []
    for bin_dir in rustlib_dir.glob("*/bin"):
        candidates.extend((bin_dir / "llvm-objcopy.exe", bin_dir / "llvm-objcopy"))
    return candidates


def resolve_objcopy(ctx: Context) -> Path | None:
    candidates: list[Path] = []

    for command_name in ("arm-none-eabi-objcopy", "rust-objcopy", "llvm-objcopy"):
        candidate = resolve_cmd(command_name)
        if candidate is not None:
            candidates.append(candidate)

    candidates.extend(_rust_sysroot_objcopy_candidates(ctx))

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None
