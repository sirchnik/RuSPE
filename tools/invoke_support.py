from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from shutil import copy2, which

from invoke.context import Context
from invoke.exceptions import Failure, UnexpectedExit


class BuildError(RuntimeError):
    """Raised when a build step cannot be completed."""


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
    ctx: Context, command: list[str], cwd: Path, extra_env: dict[str, str] | None = None
) -> None:
    command_text = _format_command(command)
    try:
        with ctx.cd(str(cwd)):
            ctx.run(command_text, env=_merge_env(extra_env), echo=True)
    except UnexpectedExit as error:
        raise BuildError(
            f"Command failed with exit code {error.result.exited}: {command_text}"
        ) from error
    except Failure as error:
        raise BuildError(f"Failed to execute command: {command_text}") from error


def _command_path(command_name: str) -> Path | None:
    resolved = which(command_name)
    return Path(resolved) if resolved else None


def resolve_openocd() -> Path | None:
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
        if candidate.exists():
            return candidate
    return None


def _rust_sysroot_objcopy_candidates(ctx: Context) -> list[Path]:
    rustc = _command_path("rustc")
    if rustc is None:
        return []

    try:
        result = ctx.run(
            f"{_format_command([str(rustc), '--print', 'sysroot'])}", hide=True
        )
        if result is None:
            return []
        sysroot = result.stdout.strip()
    except Failure:
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


def cargo_build(ctx: Context, board: BoardConfig, debug: bool) -> None:
    command = ["cargo", "build"]
    if not debug:
        command.append("--release")
    run_command(ctx, command, cwd=board.board_dir)


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
        ctx,
        [str(objcopy), "--set-section-flags", ".apps=LOAD,ALLOC", str(kernel_with_app)],
        cwd=board.board_dir,
    )
    run_command(
        ctx,
        [str(objcopy), "--update-section", f".apps={app_path}", str(kernel_with_app)],
        cwd=board.board_dir,
    )
    return kernel_with_app


def build_non_secure(
    ctx: Context, board: BoardConfig, debug: bool, app: str | None
) -> Path:
    cargo_build(ctx, board, debug)
    return inject_app(ctx, board, debug, app)


def flash_non_secure(
    ctx: Context, board: BoardConfig, debug: bool, app: str | None
) -> Path:
    kernel_with_app = build_non_secure(ctx, board, debug, app)
    run_command(
        ctx,
        ["probe-rs", "run", "--chip", board.chip, str(kernel_with_app)],
        cwd=board.board_dir,
    )
    return kernel_with_app


def program_non_secure(
    ctx: Context, board: BoardConfig, debug: bool, app: str | None
) -> Path:
    kernel_with_app = build_non_secure(ctx, board, debug, app)
    openocd = resolve_openocd()
    if openocd is None:
        raise BuildError(
            "OpenOCD was not found. Set OPENOCD_ROOT or add openocd to PATH."
        )
    if board.openocd_tcl is None or not board.openocd_tcl.exists():
        raise BuildError(f"OpenOCD configuration does not exist: {board.openocd_tcl}")

    run_command(
        ctx,
        [
            str(openocd),
            "-f",
            str(board.openocd_tcl),
            "-c",
            f"init; reset init; program {kernel_with_app}; reset; shutdown",
        ],
        cwd=board.board_dir,
    )
    return kernel_with_app


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
        ctx,
        [str(objcopy), "-O", "ihex", str(input_image), str(output_hex)],
        cwd=board_dir,
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


def build_secure_non_secure_hex(
    ctx: Context,
    secure_board: BoardConfig,
    non_secure_board: BoardConfig,
    debug: bool,
    app: str | None,
) -> Path:
    cargo_build(ctx, secure_board, debug)
    non_secure_kernel = build_non_secure(ctx, non_secure_board, debug, app)

    secure_image = secure_board.kernel_image(debug)
    if not secure_image.exists():
        raise BuildError(f"Secure image does not exist: {secure_image}")

    target_root = secure_board.target_root(debug)
    secure_hex = elf_to_hex(
        ctx,
        secure_image,
        target_root / f"{secure_board.platform}.hex",
        secure_board.board_dir,
    )
    non_secure_hex = elf_to_hex(
        ctx,
        non_secure_kernel,
        target_root / f"{non_secure_board.platform}-app.hex",
        secure_board.board_dir,
    )
    merged_hex = target_root / f"{non_secure_board.platform}_merged.hex"
    merge_hex_images(merged_hex, [secure_hex, non_secure_hex])
    print(f"Built merged secure image: {merged_hex}")
    return merged_hex


def flash_secure(
    ctx: Context,
    secure_board: BoardConfig,
    non_secure_board: BoardConfig,
    debug: bool,
    app: str | None,
) -> Path:
    merged_hex = build_secure_non_secure_hex(
        ctx, secure_board, non_secure_board, debug, app
    )
    run_command(
        ctx,
        [
            "probe-rs",
            "download",
            "--chip",
            secure_board.chip,
            "--binary-format",
            "hex",
            str(merged_hex),
        ],
        cwd=secure_board.board_dir,
    )
    return merged_hex


def program_secure(
    ctx: Context,
    secure_board: BoardConfig,
    non_secure_board: BoardConfig,
    debug: bool,
    *,
    app: str | None,
) -> Path:
    merged_hex = build_secure_non_secure_hex(
        ctx, secure_board, non_secure_board, debug, app
    )
    openocd = resolve_openocd()
    if openocd is None:
        raise BuildError(
            "OpenOCD was not found. Set OPENOCD_ROOT or add openocd to PATH."
        )
    if secure_board.openocd_tcl is None or not secure_board.openocd_tcl.exists():
        raise BuildError(
            f"OpenOCD configuration does not exist: {secure_board.openocd_tcl}"
        )

    run_command(
        ctx,
        [
            str(openocd),
            "-f",
            str(secure_board.openocd_tcl),
            "-c",
            f"init; reset init; program {merged_hex}; reset; shutdown",
        ],
        cwd=secure_board.board_dir,
    )
    return merged_hex
