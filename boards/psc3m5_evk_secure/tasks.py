from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.invoke_support import BoardConfig, build_task, cargo_build  # noqa: E402

BOARD = BoardConfig(
    board_dir=Path(__file__).resolve().parent,
    repo_root=REPO_ROOT,
    chip="PSC3M5FDS2AFQ1",
)

DEBUG_HELP = "Build the debug profile instead of release."


@build_task(default=True, help={"debug": DEBUG_HELP})
def build(ctx, debug=False):
    """Build the secure kernel ELF."""

    return cargo_build(ctx, BOARD, bool(debug))
