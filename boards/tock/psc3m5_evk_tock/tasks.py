from __future__ import annotations

import sys
from pathlib import Path

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boards.psc3m5_evk_secure import tasks as secure_tasks  # noqa: E402
from boards.tock.psa_tock_app import tasks as app_tasks  # noqa: E402
from tools.build.invoke_support import build_task  # noqa: E402
from tools.build.board import (  # noqa: E402
    BoardConfig,
    Manufacturer,
    build_non_secure,
    flash_hex,
    merge_secure_non_secure_hex,
    program_hex,
)

NON_SECURE_BOARD_DIR = Path(__file__).resolve().parent
SECURE_BOARD_DIR = NON_SECURE_BOARD_DIR.parent.parent / "psc3m5_evk_secure"

SECURE_BOARD = BoardConfig(
    board_dir=SECURE_BOARD_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_BOARD_DIR / "openocd.tcl",
)

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_BOARD_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    openocd_tcl=NON_SECURE_BOARD_DIR / "openocd.tcl",
)

APP_HELP = (
    "Path to a TBF application image to embed in the non-secure kernel. "
    "When omitted the psa_tock_app is built and used automatically."
)
DEBUG_HELP = "Build the debug profile instead of release."
TOOLS = ["cargo", "objcopy", "probe-rs", "openocd", "elf2tab"]


def _resolve_app(ctx: Context, app: str | None, debug: bool) -> str | None:
    if app is not None:
        return app
    return str(app_tasks.build(ctx, debug=debug))


def _build_merged(ctx: Context, app: str | None, debug: bool) -> Path:
    app = _resolve_app(ctx, app, debug)
    secure_elf = secure_tasks.build(ctx, debug=debug)
    non_secure_elf = build_non_secure(ctx, NON_SECURE_BOARD, debug, app)
    return merge_secure_non_secure_hex(
        ctx,
        SECURE_BOARD,
        NON_SECURE_BOARD,
        secure_elf,
        non_secure_elf,
        debug,
    )


@build_task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def build(ctx: Context, app=None, debug=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""

    return _build_merged(ctx, app, debug)


@build_task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def flash(ctx: Context, app=None, debug=False):
    """Build, merge, and flash the secure and non-secure images with probe-rs."""

    merged = _build_merged(ctx, app, debug)
    return flash_hex(ctx, SECURE_BOARD, merged)


@build_task(help={"app": APP_HELP, "debug": DEBUG_HELP})
def program(ctx: Context, app=None, debug=False):
    """Build, merge, and program the secure image with OpenOCD."""

    merged = _build_merged(ctx, app, debug)
    return program_hex(ctx, SECURE_BOARD, merged)


@build_task(default=True, help={"app": APP_HELP, "debug": DEBUG_HELP})
def install(ctx: Context, app=None, debug=False):
    """Alias for flash."""

    return flash(ctx, app=app, debug=debug)
