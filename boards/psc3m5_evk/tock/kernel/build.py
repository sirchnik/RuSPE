# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from pathlib import Path

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from integrations.tock.tock_psa_app import build as app_build
from integrations.tock.tock_interrupt_test_app import build as interrupt_app_build
from tools.build.board import (
    BoardConfig,
    Manufacturer,
    build_non_secure,
)

BOARD_DIR = Path(__file__).resolve().parent.parent
NON_SECURE_BOARD_DIR = Path(__file__).resolve().parent

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_BOARD_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    crate_name="psc3m5_evk_tock_kernel",
    openocd_tcl=BOARD_DIR / "openocd.tcl",
)


def _resolve_app(ctx: Context, app: str | None, debug: bool) -> str | None:
    if app is not None:
        return app

    app1_tbf = app_build.build(ctx, debug=debug)
    app2_tbf = interrupt_app_build.build(ctx, debug=debug)

    combined_tbf = app1_tbf.parent / "combined_apps.tbf"

    with open(app1_tbf, "rb") as f:
        app1_data = bytearray(f.read())

    pad_len = 0x4000
    if len(app1_data) > pad_len:
        raise ValueError(f"App 1 is larger than {pad_len} bytes")

    # Read old size and checksum
    old_size = int.from_bytes(app1_data[4:8], "little")
    old_checksum = int.from_bytes(app1_data[12:16], "little")

    # Calculate new checksum: old_checksum ^ old_size ^ new_size
    new_checksum = old_checksum ^ old_size ^ pad_len

    # Update size and checksum in the header
    app1_data[4:8] = pad_len.to_bytes(4, "little")
    app1_data[12:16] = new_checksum.to_bytes(4, "little")

    # Pad to pad_len
    app1_data.extend(b"\x00" * (pad_len - len(app1_data)))

    with open(combined_tbf, "wb") as f:
        f.write(app1_data)
        with open(app2_tbf, "rb") as f2:
            f.write(f2.read())

    return str(combined_tbf)


def build(ctx: Context, app: str | None = None, debug: bool = False) -> Path:
    """Build the Tock non-secure kernel."""
    app_path = _resolve_app(ctx, app, debug)
    non_secure_elf = build_non_secure(ctx, NON_SECURE_BOARD, debug, app_path)
    return non_secure_elf
