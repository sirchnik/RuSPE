from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from shutil import copy2, which

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


@dataclass(frozen=True)
class BoardConfig:
    repo_root: Path
    board_dir: Path
    chip: str
    openocd_tcl: Path | None = None

    @property
    def platform(self) -> str:
        return self.board_dir.name

    def build_type(self, debug: bool) -> str:
        return "debug" if debug else "release"

    def target_root(self, debug: bool) -> Path:
        return (
            self.repo_root
            / "target"
            / "thumbv8m.main-none-eabi"
            / self.build_type(debug)
        )

    def kernel_image(self, debug: bool) -> Path:
        return self.target_root(debug) / self.platform


def _format_command(command: list[str]) -> str:
    return subprocess.list2cmdline(command)


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
        reset = "\x1b[0m"
        grey = "\x1b[90m"
        envs = ""
        if env:
            items = [f"{k}={v}" for k, v in list(env.items())[:4]]
            envs = (" ".join(items) + ("..." if len(env) > 4 else "")) + " "
        compact = f"{grey}cd {cwd or Path.cwd()} && {envs}{cmd_text} {reset}"
        print(compact)

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


def _command_path(command_name: str) -> Path | None:
    add_paths = [str(Path.home() / ".cargo" / "bin")]
    path = path = (os.environ.get("PATH") or "") + ":" + (":".join(add_paths))
    resolved = which(command_name, path=path)
    return Path(resolved) if resolved else None


def resolve_openocd(version="default") -> Path | None:
    candidates: list[Path] = []
    openocd_root = os.environ.get("OPENOCD_ROOT")
    if openocd_root:
        root_path = Path(openocd_root)
        candidates.extend(
            (root_path / "bin" / "openocd.exe", root_path / "bin" / "openocd")
        )

    path_candidate = _command_path("openocd")
    if path_candidate is not None:
        candidates.append(path_candidate)

    for candidate in candidates:
        if version == "infineon":
            if is_infineon_openocd(candidate):
                return candidate
        elif candidate.exists():
            return candidate
    raise BuildError("OpenOCD was not found. Set OPENOCD_ROOT or add openocd to PATH.")


def is_infineon_openocd(openocd_bin: Path) -> bool:
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


def _rust_sysroot_objcopy_candidates(ctx: Context) -> list[Path]:
    rustc = _command_path("rustc")
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
        candidate = _command_path(command_name)
        if candidate is not None:
            candidates.append(candidate)

    candidates.extend(_rust_sysroot_objcopy_candidates(ctx))

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def cargo_build(ctx: Context, board: BoardConfig, debug: bool) -> Path:
    command = ["cargo", "build"]
    if not debug:
        command.append("--release")
    run_command(command, cwd=board.board_dir)
    return board.kernel_image(debug)


def inject_app(ctx: Context, board: BoardConfig, debug: bool, app: str | None) -> Path:
    kernel = board.kernel_image(debug)
    kernel_with_app = board.target_root(debug) / f"{board.platform}-app.elf"

    if not kernel.exists():
        raise BuildError(f"Kernel image does not exist: {kernel}")

    if not app:
        copy2(kernel, kernel_with_app)
        print("Built kernel without embedding an application image.")
        return kernel_with_app

    app_path = Path(app)
    if not app_path.is_absolute():
        app_path = Path.cwd() / app_path
    app_path = app_path.resolve()

    if not app_path.exists():
        raise BuildError(f"Application image does not exist: {app_path}")

    objcopy = resolve_objcopy(ctx)
    if objcopy is None:
        raise BuildError(
            "Required tool not found: rust-objcopy or llvm-objcopy. Install 'llvm-tools-preview' and 'cargo-binutils'."
        )

    copy2(kernel, kernel_with_app)
    run_command(
        [str(objcopy), "--set-section-flags", ".apps=LOAD,ALLOC", str(kernel_with_app)],
        cwd=board.board_dir,
    )
    run_command(
        [str(objcopy), "--update-section", f".apps={app_path}", str(kernel_with_app)],
        cwd=board.board_dir,
    )
    return kernel_with_app


def build_non_secure(
    ctx: Context, board: BoardConfig, debug: bool, app: str | None
) -> Path:
    cargo_build(ctx, board, debug)
    return inject_app(ctx, board, debug, app)


def elf_to_hex(
    ctx: Context, input_image: Path, output_hex: Path, board_dir: Path
) -> Path:
    objcopy = resolve_objcopy(ctx)
    if objcopy is None:
        raise BuildError(
            "Required tool not found: rust-objcopy or llvm-objcopy. Install 'llvm-tools-preview' and 'cargo-binutils'."
        )

    output_hex.parent.mkdir(parents=True, exist_ok=True)
    run_command(
        [str(objcopy), "-O", "ihex", str(input_image), str(output_hex)], cwd=board_dir
    )
    return output_hex


def merge_hex_images(output_path: Path, input_paths: list[Path]) -> Path:
    try:
        from intelhex import IntelHex
    except ImportError as error:
        raise BuildError("Python module 'intelhex' is not installed.") from error

    print(f"Merging HEX images with intelhex into {output_path}")

    merged = IntelHex()
    for image_path in input_paths:
        print(f"  - loading {image_path}")
        image = IntelHex(str(image_path))
        merged.merge(image, overlap="ignore")

    merged.start_addr = None
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.write_hex_file(str(output_path))
    return output_path


def merge_secure_non_secure_hex(
    ctx: Context,
    secure_board: BoardConfig,
    non_secure_board: BoardConfig,
    secure_elf: Path,
    non_secure_elf: Path,
    debug: bool,
) -> Path:
    if not secure_elf.exists():
        raise BuildError(f"Secure image does not exist: {secure_elf}")

    target_root = secure_board.target_root(debug)
    secure_hex = elf_to_hex(
        ctx,
        secure_elf,
        target_root / f"{secure_board.platform}.hex",
        secure_board.board_dir,
    )
    non_secure_hex = elf_to_hex(
        ctx,
        non_secure_elf,
        target_root / f"{non_secure_board.platform}-app.hex",
        secure_board.board_dir,
    )
    merged_hex = target_root / f"{non_secure_board.platform}_merged.hex"
    merge_hex_images(merged_hex, [secure_hex, non_secure_hex])
    print(f"Built merged secure image: {merged_hex}")
    return merged_hex


def flash_hex(ctx: Context, board: BoardConfig, hex_path: Path) -> Path:
    run_command(
        [
            "probe-rs",
            "download",
            "--chip",
            board.chip,
            "--binary-format",
            "hex",
            str(hex_path),
        ],
        cwd=board.board_dir,
    )
    return hex_path


def program_hex(ctx: Context, board: BoardConfig, hex_path: Path, options={}) -> Path:
    if options.get("OPENOCD_IS_IFX", None):
        openocd = resolve_openocd(version="infineon")
    else:
        openocd = resolve_openocd()
    if board.openocd_tcl is None or not board.openocd_tcl.exists():
        raise BuildError(f"OpenOCD configuration does not exist: {board.openocd_tcl}")

    run_command(
        [
            str(openocd),
            "-f",
            str(board.openocd_tcl),
            "-c",
            f"init; reset init; program {hex_path}; reset; shutdown",
        ],
        cwd=board.board_dir,
    )
    return hex_path
