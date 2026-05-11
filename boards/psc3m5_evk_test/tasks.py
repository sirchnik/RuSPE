from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boards.psc3m5_evk_secure import tasks as secure_tasks  # noqa: E402
from tools.invoke_support import (  # noqa: E402
    BoardConfig,
    build_non_secure,
    build_task,
    flash_hex,
    merge_secure_non_secure_hex,
    program_hex,
)


NON_SECURE_DIR = Path(__file__).resolve().parent
SECURE_BOARD_DIR = NON_SECURE_DIR.parent / "psc3m5_evk_secure"

SECURE_BOARD = BoardConfig(
    board_dir=SECURE_BOARD_DIR,
    repo_root=REPO_ROOT,
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_DIR / "openocd.tcl",
)

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_DIR,
    repo_root=REPO_ROOT,
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_DIR / "openocd.tcl",
)

DEBUG_HELP = "Build the debug profile instead of release."
TOOLS = ["cargo", "objcopy", "probe-rs", "openocd"]


def _build_merged(ctx, debug: bool) -> Path:
    secure_elf = secure_tasks.build(ctx, debug=debug)
    non_secure_elf = build_non_secure(ctx, NON_SECURE_BOARD, debug, app=None)
    return merge_secure_non_secure_hex(
        ctx,
        SECURE_BOARD,
        NON_SECURE_BOARD,
        secure_elf,
        non_secure_elf,
        debug,
    )


@build_task(help={"debug": DEBUG_HELP})
def build(ctx, debug=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""

    return _build_merged(ctx, bool(debug))


@build_task(help={"debug": DEBUG_HELP})
def flash(ctx, debug=False):
    """Build, merge, and flash the secure and non-secure images with probe-rs."""

    merged = _build_merged(ctx, bool(debug))
    return flash_hex(ctx, SECURE_BOARD, merged)


@build_task(help={"debug": DEBUG_HELP})
def program(ctx, debug=False):
    """Build, merge, and program the secure image with OpenOCD."""

    merged = _build_merged(ctx, bool(debug))
    return program_hex(ctx, SECURE_BOARD, merged)


@build_task(default=True, help={"debug": DEBUG_HELP})
def install(ctx, debug=False):
    """Alias for flash."""

    return flash(ctx, debug=debug)
