# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from pathlib import Path

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build.board import ( 
    BoardConfig,
    Manufacturer,
    cargo_build,
)

BOARD_DIR = Path(__file__).resolve().parent.parent 
NON_SECURE_DIR = Path(__file__).resolve().parent

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    crate_name="psc3m5_evk_test_nspe",
    openocd_tcl=BOARD_DIR / "openocd.tcl",
)

def build(ctx: Context, debug: bool = False) -> Path:
    """Build the test non-secure kernel."""
    return cargo_build(ctx, NON_SECURE_BOARD, debug)
