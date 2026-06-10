# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from pathlib import Path

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build.invoke_support import build_task  
from tools.build.board import ( 
    BoardConfig,
    Manufacturer,
    build_non_secure,
    cargo_build,
    elf_to_hex,
    merge_hex_images,
)
from tools.build.service import ServiceConfig, cargo_build_service 

BOARD = BoardConfig(
    board_dir=Path(__file__).resolve().parent,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
)

SERVICES_DIR = REPO_ROOT / "boards" / "services"
NON_SECURE_DIR = REPO_ROOT / "boards" / "psc3m5_evk_test"

ATTEST_SERVICE = ServiceConfig(
    service_dir=SERVICES_DIR / "attest",
    repo_root=REPO_ROOT,
    flash_origin="0x3201_0000",
    flash_length="0x3F00",
    ram_origin="0x3400_2F00",
    ram_length="0x1100",
)

NON_SECURE_BOARD = BoardConfig(
    board_dir=NON_SECURE_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
)

DEBUG_HELP = "Build the debug profile instead of release."


@build_task(default=True, help={"debug": DEBUG_HELP})
def build(ctx: Context, debug=False):
    """Build secure IPC + attest service + psc3m5_evk_test non-secure image and merge HEX."""
    debug = bool(debug)

    # 1. Build the attest service binary
    attest_elf = cargo_build_service(ctx, ATTEST_SERVICE, debug)

    # 2. Build the secure IPC kernel with service address in environment
    kernel_elf = cargo_build(ctx, BOARD, debug, env=ATTEST_SERVICE.linker_env())

    # 3. Build the non-secure test image
    non_secure_elf = build_non_secure(ctx, NON_SECURE_BOARD, debug, app=None)

    # 4. Convert all images to HEX and merge
    target_root = BOARD.target_root(debug)
    kernel_hex = elf_to_hex(ctx, kernel_elf, target_root / "psc3m5_evk_secure_ipc.hex", BOARD.board_dir)
    attest_hex = elf_to_hex(
        ctx,
        attest_elf,
        target_root / "psc3m5_evk_attest.hex",
        ATTEST_SERVICE.service_dir,
    )
    non_secure_hex = elf_to_hex(
        ctx,
        non_secure_elf,
        target_root / "psc3m5_evk_test-app.hex",
        NON_SECURE_BOARD.board_dir,
    )

    merged = merge_hex_images(
        target_root / "psc3m5_evk_secure_ipc_merged.hex",
        [kernel_hex, attest_hex, non_secure_hex],
    )
    print(f"Merged image: {merged}")
    return merged
