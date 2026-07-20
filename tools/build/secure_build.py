# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Common orchestration for building a merged secure + non-secure firmware image."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from invoke.context import Context

from tools.build.board import (
    BoardConfig,
    cargo_build,
    elf_to_hex,
    merge_secure_non_secure_hex,
)
from tools.build.mcuboot import patch_mcuboot_sig
from tools.build.tock_app import TockAppsLayout, build_tock_apps


@dataclass(frozen=True)
class McubootConfig:
    """MCUboot signing addresses for a board."""

    mcuboot_addr: int
    payload_start: int
    payload_end: int


@dataclass
class FirmwareResult:
    """Everything produced by a firmware build."""

    secure_elf: Path
    secure_hex: Path
    non_secure_elf: Path
    merged_hex: Path
    tock_noapps_bin: Path | None = None
    tock_apps_tbf: Path | None = None
    mcuboot_sig_bin: Path | None = None


def _extract_mcuboot_sig_bin(
    secure_hex: Path, secure_elf: Path, board: BoardConfig, mcuboot: McubootConfig
) -> Path:
    """Extract the MCUboot signature bytes to a small binary (needed for QEMU)."""
    from intelhex import IntelHex

    ih = IntelHex(str(secure_hex))
    sig_data = ih.tobinarray(start=mcuboot.mcuboot_addr, end=mcuboot.mcuboot_addr + 75)
    sig_bin = secure_elf.with_name(f"{board.prefixed_platform}_mcuboot_sig.bin")
    with open(sig_bin, "wb") as f:
        f.write(sig_data)
    return sig_bin


def build_firmware(
    ctx: Context,
    board: BoardConfig,
    nspe: str,
    app: str | None,
    debug: bool,
    *,
    mcuboot: McubootConfig,
    tock_layout: TockAppsLayout,
    test_nspe_build_module: Any,
    tock_kernel_build_module: Any,
    features: list[str] | None = None,
    cargo_env: dict[str, str] | None = None,
    extra_hexes: list[Path] | None = None,
    extract_mcuboot_sig: bool = False,
) -> FirmwareResult:
    """Build secure crate → hex → mcuboot patch → NSPE → merge.

    This is the single orchestration function replacing the per-board
    ``_build_merged`` copies.
    """
    secure_elf = cargo_build(ctx, board, debug, env=cargo_env)

    target_root = board.target_root(debug)
    secure_hex = target_root / f"{board.prefixed_platform}.hex"
    elf_to_hex(ctx, secure_elf, secure_hex)

    patch_mcuboot_sig(
        secure_hex,
        mcuboot_addr=mcuboot.mcuboot_addr,
        payload_start=mcuboot.payload_start,
        payload_end=mcuboot.payload_end,
    )

    mcuboot_sig_bin = None
    if extract_mcuboot_sig:
        mcuboot_sig_bin = _extract_mcuboot_sig_bin(secure_hex, secure_elf, board, mcuboot)

    tock_noapps_bin = None
    tock_apps_tbf = None

    if nspe == "test":
        non_secure_elf = test_nspe_build_module.build(ctx, debug=debug)
        nspe_board = test_nspe_build_module.NON_SECURE_BOARD
    elif nspe == "tock":
        if app is None:
            app_path = build_tock_apps(ctx, tock_layout, debug, features)
            tock_apps_tbf = app_path
        else:
            app_path = Path(app)
        non_secure_elf = tock_kernel_build_module.build(ctx, app=app_path, debug=debug)
        nspe_board = tock_kernel_build_module.NON_SECURE_BOARD
        tock_noapps_bin = non_secure_elf.with_name(
            f"{nspe_board.prefixed_platform}-noapps.bin"
        )
    else:
        raise ValueError(f"Unknown NSPE: {nspe}")

    all_extra_hexes = list(extra_hexes) if extra_hexes else []

    merged_hex = merge_secure_non_secure_hex(
        ctx,
        board,
        nspe_board,
        secure_hex,
        non_secure_elf,
        debug,
        all_extra_hexes,
    )

    return FirmwareResult(
        secure_elf=secure_elf,
        secure_hex=secure_hex,
        non_secure_elf=non_secure_elf,
        merged_hex=merged_hex,
        tock_noapps_bin=tock_noapps_bin,
        tock_apps_tbf=tock_apps_tbf,
        mcuboot_sig_bin=mcuboot_sig_bin,
    )
