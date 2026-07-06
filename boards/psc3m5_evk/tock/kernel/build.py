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


def build(ctx: Context, app: str | Path | None = None, debug: bool = False) -> Path:
    """Build the Tock non-secure kernel."""
    app_path = str(app) if app is not None else None
    non_secure_elf = build_non_secure(ctx, NON_SECURE_BOARD, debug, app_path)
    return non_secure_elf

