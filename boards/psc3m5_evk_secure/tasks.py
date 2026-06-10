from __future__ import annotations

import sys
from pathlib import Path

from invoke.tasks import task

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.invoke_support import BoardConfig, cargo_build, handle_build_errors  # noqa: E402

BOARD = BoardConfig(
    board_dir=Path(__file__).resolve().parent,
    repo_root=REPO_ROOT,
    chip="PSC3M5FDS2AFQ1",
)

DEBUG_HELP = "Build the debug profile instead of release."


@task(default=True, help={"debug": DEBUG_HELP})
@handle_build_errors
def build(ctx, debug=False):
    """Build the secure kernel ELF."""

    return cargo_build(ctx, BOARD, bool(debug))
