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

from boards.psc3m5_evk.secure import tasks as secure_tasks
from boards.psc3m5_evk.secure_ipc import tasks as secure_ipc_tasks
from tools.build.invoke_support import ( 
    build_task,
)
from tools.build.board import ( 
    BoardConfig,
    Manufacturer,
    cargo_build,
    flash_hex,
    merge_secure_non_secure_hex,
    program_hex,
)

BOARD_DIR = Path(__file__).resolve().parent.parent 
NON_SECURE_DIR = Path(__file__).resolve().parent
SECURE_BOARD_FN_DIR = NON_SECURE_DIR.parent / "secure"
SECURE_BOARD_IPC_DIR = NON_SECURE_DIR.parent / "secure_ipc"

SECURE_BOARD_FN = BoardConfig(
    board_dir=SECURE_BOARD_FN_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    crate_name="psc3m5_evk_secure",
    openocd_tcl=BOARD_DIR / "openocd.tcl",
)

SECURE_BOARD_IPC = BoardConfig(
    board_dir=SECURE_BOARD_IPC_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    crate_name="psc3m5_evk_secure_ipc",
    openocd_tcl=BOARD_DIR / "openocd.tcl",
)

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    crate_name="psc3m5_evk_test_nspe",
    openocd_tcl=BOARD_DIR / "openocd.tcl",
)

DEBUG_HELP = "Build the debug profile instead of release."
IPC_HELP = "Build with the secure IPC kernel instead of the function-style kernel."
TOOLS = ["cargo", "objcopy", "probe-rs", "openocd"]


def _build_merged(ctx: Context, debug: bool, ipc: bool) -> Path:
    if ipc:
        secure_elf, services = secure_ipc_tasks.build(ctx, debug=debug)
        secure_board = SECURE_BOARD_IPC
        extra_hexes = [s.hex_path for s in services]
    else:
        secure_elf = secure_tasks.build(ctx, debug=debug)
        secure_board = SECURE_BOARD_FN
        extra_hexes = []

    non_secure_elf = cargo_build(ctx, NON_SECURE_BOARD, debug)
    return merge_secure_non_secure_hex(
        ctx,
        secure_board,
        NON_SECURE_BOARD,
        secure_elf,
        non_secure_elf,
        debug,
        extra_hexes,
    )


@build_task(help={"debug": DEBUG_HELP, "ipc": IPC_HELP})
def build(ctx: Context, debug=False, ipc=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""

    return _build_merged(ctx, bool(debug), bool(ipc))


@build_task(help={"debug": DEBUG_HELP, "ipc": IPC_HELP})
def flash(ctx: Context, debug=False, ipc=False):
    """Build, merge, and flash the secure and non-secure images with probe-rs."""

    merged = _build_merged(ctx, bool(debug), bool(ipc))
    secure_board = SECURE_BOARD_IPC if ipc else SECURE_BOARD_FN
    return flash_hex(ctx, secure_board, merged)


@build_task(help={"debug": DEBUG_HELP, "ipc": IPC_HELP})
def program(ctx: Context, debug=False, ipc=False):
    """Build, merge, and program the secure image with OpenOCD."""

    merged = _build_merged(ctx, bool(debug), bool(ipc))
    secure_board = SECURE_BOARD_IPC if ipc else SECURE_BOARD_FN
    return program_hex(ctx, secure_board, merged)
