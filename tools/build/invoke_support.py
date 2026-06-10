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

from invoke.context import Context
from invoke.exceptions import Exit
from invoke.tasks import task


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


def _format_command(command: list[str]) -> str:
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
) -> None:
    """Run a command using subprocess (no Invoke context required).

    - `command` may be a list (preferred) or a shell string.
    - `cwd` may be a Path or string. If None current cwd is used.
    - `in_stream=False` will disable stdin (use DEVNULL).
    - `RUN_HANDLER_VERBOSE=0` in env disables the compact printout.
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
    cmd_text = command if isinstance(command, str) else _format_command(command)

    if in_stream is None:
        in_stream = not _is_sandbox()

    if verbose:
        envs = ""
        if env:
            items = [f"{k}={v}" for k, v in list(env.items())[:4]]
            envs = (" ".join(items) + ("..." if len(env) > 4 else "")) + " "
        compact = f"cd {cwd or Path.cwd()} && {envs}{cmd_text}"
        print_step(compact)

    stdin = None if in_stream else subprocess.DEVNULL

    try:
        if isinstance(command, str):
            subprocess.run(
                command,
                cwd=str(cwd) if cwd is not None else None,
                env=merged_env,
                shell=True,
                check=True,
                stdin=stdin,
            )
        else:
            subprocess.run(
                command,
                cwd=str(cwd) if cwd is not None else None,
                env=merged_env,
                check=True,
                stdin=stdin,
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

    for command_name in ("rust-objcopy", "llvm-objcopy"):
        candidate = resolve_cmd(command_name)
        if candidate is not None:
            candidates.append(candidate)

    candidates.extend(_rust_sysroot_objcopy_candidates(ctx))

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None
