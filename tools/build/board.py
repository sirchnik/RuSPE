# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from shutil import copy2

from invoke.context import Context

from tools.build.invoke_support import (
    print_step,
    resolve_openocd,
    BuildError,
    resolve_objcopy,
    run_command,
)


class Manufacturer(Enum):
    INFINEON = "infineon"
    OTHER = "other"


@dataclass(frozen=True)
class BoardConfig:
    repo_root: Path
    board_dir: Path
    chip: str
    manufacturer: Manufacturer
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


def _cargo_package_name(crate_dir: Path) -> str:
    cargo_toml = crate_dir / "Cargo.toml"
    if not cargo_toml.exists():
        return crate_dir.name

    try:
        data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
        package = data.get("package", {})
        name = package.get("name")
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass

    return crate_dir.name


def _candidate_artifacts(target_dir: Path, build_type: str, binary_name: str) -> list[Path]:
    names = [binary_name]
    underscored = binary_name.replace("-", "_")
    if underscored != binary_name:
        names.append(underscored)

    candidates: list[Path] = []
    for name in names:
        candidates.extend(
            [
                target_dir / "thumbv8m.main-none-eabi" / build_type / name,
                target_dir / "thumbv8m.main-none-eabi" / build_type / f"{name}.elf",
                target_dir / build_type / name,
                target_dir / build_type / f"{name}.elf",
                target_dir / build_type / f"{name}.exe",
            ]
        )
    return candidates


def _resolve_cargo_artifact(repo_root: Path, debug: bool, binary_name: str) -> Path:
    build_type = "debug" if debug else "release"
    target_dir = repo_root / "target"

    for candidate in _candidate_artifacts(target_dir, build_type, binary_name):
        if candidate.exists():
            return candidate

    # Fallback: cargo may place binaries under target/<build>/deps with hash suffixes.
    search_root = target_dir / build_type
    if search_root.exists():
        for pattern in (
            f"{binary_name}*",
            f"{binary_name.replace('-', '_')}*",
        ):
            for match in search_root.rglob(pattern):
                if match.is_file() and match.suffix in ("", ".elf", ".exe"):
                    return match

    raise BuildError(
        f"Built artifact not found for '{binary_name}' in target directory: {target_dir}"
    )


def cargo_build(ctx: Context, board: BoardConfig, debug: bool, env: dict[str, str] | None = None) -> Path:
    command = ["cargo", "build"]
    if not debug:
        command.append("--release")
    run_command(command, cwd=board.board_dir, env=env)
    binary_name = _cargo_package_name(board.board_dir)
    return _resolve_cargo_artifact(board.repo_root, debug, binary_name)


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
    ctx: Context, input_image: Path, output_hex: Path
) -> Path:
    objcopy = resolve_objcopy(ctx)
    if objcopy is None:
        raise BuildError(
            "Required tool not found: rust-objcopy or llvm-objcopy. Install 'llvm-tools-preview' and 'cargo-binutils'."
        )

    output_hex.parent.mkdir(parents=True, exist_ok=True)
    run_command(
        [str(objcopy), "-O", "ihex", str(input_image), str(output_hex)]
    )
    return output_hex


def merge_hex_images(output_path: Path, input_paths: list[Path]) -> Path:
    try:
        from intelhex import AddressOverlapError, IntelHex
    except ImportError as error:
        raise BuildError("Python module 'intelhex' is not installed.") from error

    print_step(f"Merging HEX images with intelhex into {output_path}")

    merged = IntelHex()
    for image_path in input_paths:
        print_step(f"  - loading {image_path}")
        image = IntelHex(str(image_path))
        image.start_addr = None
        try:
            merged.merge(image, overlap="error")
        except AddressOverlapError as error:
            raise BuildError(
                f"HEX image overlap detected while merging {image_path} into {output_path}: {error}"
            ) from error

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
    )
    non_secure_hex = elf_to_hex(
        ctx,
        non_secure_elf,
        target_root / f"{non_secure_board.platform}-app.hex",
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


def program_hex(ctx: Context, board: BoardConfig, hex_path: Path) -> Path:
    if board.manufacturer is Manufacturer.INFINEON:
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
