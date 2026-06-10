from __future__ import annotations

import sys
from pathlib import Path

from invoke.tasks import task

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.invoke_support import (  # noqa: E402
    BoardConfig,
    build_secure_non_secure_hex,
    flash_secure,
    print_check_summary,
    program_secure,
)


BOARD_DIR = Path(__file__).resolve().parent
NON_SECURE_DIR = BOARD_DIR.parent / "psc3m5_evk"

SECURE_BOARD = BoardConfig(
    board_dir=BOARD_DIR,
    platform="psc3m5_evk_secure",
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_DIR / "openocd.tcl",
)

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_DIR,
    platform="psc3m5_evk",
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_DIR / "openocd.tcl",
)

APP_HELP = "Path to a TBF application image to embed in the non-secure kernel."
DEBUG_HELP = "Build the debug profile instead of release."
TOOLS = ["cargo", "objcopy", "probe-rs", "openocd"]


@task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def build(ctx, app="", debug=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""

    build_secure_non_secure_hex(ctx, SECURE_BOARD, NON_SECURE_BOARD, bool(debug), app or None)


@task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def flash(ctx, app="", debug=False):
    """Build, merge, and flash the secure and non-secure images with probe-rs."""

    flash_secure(ctx, SECURE_BOARD, NON_SECURE_BOARD, bool(debug), app or None)


@task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def program(ctx, app="", debug=False):
    """Build, merge, and program the secure image with OpenOCD."""

    program_secure(ctx, SECURE_BOARD, NON_SECURE_BOARD, bool(debug), app or None)


@task(default=True, help={"app": APP_HELP, "debug": DEBUG_HELP})
def install(ctx, app="", debug=False):
    """Alias for flash."""

    flash(ctx, app=app, debug=debug)


@task(name="check-tools")
def check_tools(ctx):
    """Check that all tools needed by this board are installed."""

    print_check_summary(
        ctx,
        TOOLS,
        ["invoke", "intelhex"],
    )
