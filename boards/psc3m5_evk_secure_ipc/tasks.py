from __future__ import annotations

import sys
from pathlib import Path

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build.invoke_support import build_task  # noqa: E402
from tools.build.board import (  # noqa: E402
    BoardConfig,
    Manufacturer,
    cargo_build,
)

BOARD = BoardConfig(
    board_dir=Path(__file__).resolve().parent,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
)

DEBUG_HELP = "Build the debug profile instead of release."


@build_task(default=True, help={"debug": DEBUG_HELP})
def build(ctx: Context, debug=False):
    """Build the secure kernel ELF (IPC model with embedded services)."""

    return cargo_build(ctx, BOARD, bool(debug))
