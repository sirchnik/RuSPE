# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Shared helpers for building Tock userland applications."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from invoke.context import Context

from .invoke_support import (
    BuildError,
    run_command,
    resolve_cmd,
)


@dataclass(frozen=True)
class TockAppConfig:
    """Configuration for a single Tock userland application."""

    repo_root: Path
    app_dir: Path
    app_name: str
    flash_start: str
    flash_length: str
    ram_start: str
    ram_length: str
    veneer_board: str | None = None

    def build_type(self, debug: bool) -> str:
        return "debug" if debug else "release"

    def target_root(self, debug: bool) -> Path:
        return (
            self.repo_root
            / "target"
            / "thumbv8m.main-none-eabi"
            / self.build_type(debug)
        )

    def elf_image(self, debug: bool) -> Path:
        return self.target_root(debug) / self.app_name

    def tbf_image(self, debug: bool) -> Path:
        return self.target_root(debug) / f"{self.app_name}.tbf"

    def linker_env(self) -> dict[str, str]:
        return {
            "LIBTOCK_LINKER_FLASH": self.flash_start,
            "LIBTOCK_LINKER_FLASH_LENGTH": self.flash_length,
            "LIBTOCK_LINKER_RAM": self.ram_start,
            "LIBTOCK_LINKER_RAM_LENGTH": self.ram_length,
        }


def _cargo_package_name(crate_dir: Path) -> str:
    import tomllib

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


def _resolve_veneer_obj(app: TockAppConfig) -> Path:
    if app.veneer_board is None:
        raise BuildError("veneer_board must be provided when linking secure veneers")

    board_dir_out_of_tree = app.repo_root.parent / "boards" / app.veneer_board
    build_root = app.repo_root.parent if board_dir_out_of_tree.exists() else app.repo_root

    board_obj_name = f"{app.veneer_board}_secure-veneers.o"
    veneer_obj = (
        build_root / "target" / "thumbv8m.main-none-eabi" / board_obj_name
    ).resolve()

    if veneer_obj.exists():
        return veneer_obj

    raise BuildError(
        "Could not find secure veneers object file at expected path:\n"
        f"  - {veneer_obj}\n"
        "Make sure the secure firmware was built first so the veneer object is generated."
    )


def cargo_build_app(
    ctx: Context,
    app: TockAppConfig,
    debug: bool,
    features: list[str] | None = None,
) -> Path:
    """Build a single Tock app, using ``cargo rustc`` when veneers are needed."""
    if app.veneer_board is not None:
        command: list[str] = ["cargo", "rustc"]
        if not debug:
            command.append("--release")
        if features:
            command.extend(["--features", ",".join(features)])
        veneer_obj = _resolve_veneer_obj(app)
        command.extend(["--", "-C", f"link-arg={veneer_obj}"])
    else:
        command = ["cargo", "build"]
        if not debug:
            command.append("--release")

    run_command(command, cwd=app.app_dir, env=app.linker_env())

    raw_elf_name = _cargo_package_name(app.app_dir)
    raw_elf = app.target_root(debug) / raw_elf_name
    target_elf = app.elf_image(debug)

    if raw_elf != target_elf and raw_elf.exists():
        from shutil import copy2

        copy2(raw_elf, target_elf)

    return target_elf


def elf_to_tbf(
    ctx: Context,
    app: TockAppConfig,
    debug: bool,
    features: list[str] | None = None,
) -> Path:
    """Build a Tock app and convert the resulting ELF to TBF format."""
    elf = cargo_build_app(ctx, app, debug, features=features)
    if not elf.exists():
        raise BuildError(f"App ELF does not exist: {elf}")

    tbf = app.tbf_image(debug)
    tab = tbf.with_suffix(".tab")
    elf2tab = resolve_cmd("elf2tab")
    if elf2tab is None:
        raise BuildError("elf2tab tool not found in PATH")
    run_command(
        [
            str(elf2tab),
            "--kernel-major",
            "2",
            "--kernel-minor",
            "1",
            "-n",
            app.app_name,
            "-o",
            str(tab),
            str(elf),
        ],
        cwd=app.app_dir,
    )

    if not tbf.exists():
        raise BuildError(f"elf2tab did not produce expected TBF file: {tbf}")

    return tbf


# ---------------------------------------------------------------------------
# Board-level Tock app memory layout
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TockAppSlot:
    """Memory slot assignment for a tock app on a specific board."""

    flash_start: str
    flash_length: str
    ram_start: str
    ram_length: str


@dataclass(frozen=True)
class TockAppsLayout:
    """Board-level memory map for the default set of tock apps."""

    board: str
    psa_app: TockAppSlot
    interrupt_test_app: TockAppSlot
    pad_len: int = 0x4000


def build_tock_apps(
    ctx: Context,
    layout: TockAppsLayout,
    debug: bool,
    features: list[str] | None = None,
) -> Path:
    """Build both default tock apps, combine them, and return the combined TBF path."""
    from integrations.tock.tock_psa_app import build as tock_psa_app_build
    from integrations.tock.tock_interrupt_test_app import (
        build as tock_interrupt_test_app_build,
    )
    from .board import combine_tock_apps

    app1_tbf = tock_psa_app_build.build(
        ctx,
        board=layout.board,
        flash_start=layout.psa_app.flash_start,
        flash_length=layout.psa_app.flash_length,
        ram_start=layout.psa_app.ram_start,
        ram_length=layout.psa_app.ram_length,
        debug=debug,
        features=features,
    )
    app2_tbf = tock_interrupt_test_app_build.build(
        ctx,
        flash_start=layout.interrupt_test_app.flash_start,
        flash_length=layout.interrupt_test_app.flash_length,
        ram_start=layout.interrupt_test_app.ram_start,
        ram_length=layout.interrupt_test_app.ram_length,
        debug=debug,
    )
    return combine_tock_apps(app1_tbf, app2_tbf, pad_len=layout.pad_len, board=layout.board)
