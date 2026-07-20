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

from tools.build.tock_app import TockAppConfig, elf_to_tbf

APP_DIR = Path(__file__).resolve().parent


def build(
    ctx: Context,
    board: str,
    flash_start: str,
    flash_length: str,
    ram_start: str,
    ram_length: str,
    debug: bool = False,
    features: list[str] | None = None,
) -> Path:
    """Build the Tock userland app and convert it to TBF."""
    app = TockAppConfig(
        repo_root=REPO_ROOT,
        app_dir=APP_DIR,
        app_name="tock_psa_app",
        flash_start=flash_start,
        flash_length=flash_length,
        ram_start=ram_start,
        ram_length=ram_length,
        veneer_board=board,
    )
    return elf_to_tbf(ctx, app, bool(debug), features=features)
