from __future__ import annotations

import sys
from pathlib import Path

from invoke.tasks import task

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.invoke_support import (  # noqa: E402
    BoardConfig,
    build_secure_non_secure_hex,
    flash_secure,
    program_secure,
)


NON_SECURE_BOARD_DIR = Path(__file__).resolve().parent
SECURE_BOARD_DIR = NON_SECURE_BOARD_DIR.parent.parent / "psc3m5_evk_secure"

SECURE_BOARD = BoardConfig(
    board_dir=SECURE_BOARD_DIR,
    repo_root=REPO_ROOT,
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_BOARD_DIR / "openocd.tcl",
)

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_BOARD_DIR,
    repo_root=REPO_ROOT,
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_BOARD_DIR / "openocd.tcl",
)

APP_HELP = "Path to a TBF application image to embed in the non-secure kernel."
DEBUG_HELP = "Build the debug profile instead of release."
TOOLS = ["cargo", "objcopy", "probe-rs", "openocd"]


@task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def build(ctx, app=None, debug=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""

    build_secure_non_secure_hex(
        ctx, SECURE_BOARD, NON_SECURE_BOARD, bool(debug), app=app
    )


@task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def flash(ctx, app=None, debug=False):
    """Build, merge, and flash the secure and non-secure images with probe-rs."""

    flash_secure(ctx, SECURE_BOARD, NON_SECURE_BOARD, bool(debug), app=app)


@task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def program(ctx, app=None, debug=False):
    """Build, merge, and program the secure image with OpenOCD."""

    program_secure(ctx, SECURE_BOARD, NON_SECURE_BOARD, bool(debug), app=app)


@task(default=True, help={"app": APP_HELP, "debug": DEBUG_HELP})
def install(ctx, app=None, debug=False):
    """Alias for flash."""

    flash(ctx, app=app, debug=debug)
