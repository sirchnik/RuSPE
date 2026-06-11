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

from tools.build.invoke_support import (
    build_task,
    VscodeLaunchTarget,
    VscodeBuildTarget,
    vscode_common_build_task,
    get_vscode_build_commands,
)
from tools.build.board import ( 
    BoardConfig,
    Manufacturer,
    cargo_build,
    flash_hex,
    merge_secure_non_secure_hex,
    program_hex,
)

from boards.psc3m5_evk.test_nspe import build as test_nspe_build
from boards.psc3m5_evk.tock.kernel import build as tock_kernel_build

BOARD_DIR = Path(__file__).resolve().parent

BOARD = BoardConfig(
    board_dir=BOARD_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    crate_name="psc3m5_evk_secure",
    openocd_tcl=BOARD_DIR.parent / "openocd.tcl",
)

DEBUG_HELP = "Build the debug profile instead of release."
NSPE_HELP = "The Non-Secure Processing Environment to build (test or tock)."
APP_HELP = "Path to a TBF application image (only for tock NSPE)."


def _build_merged(ctx: Context, nspe: str, app: str | None, debug: bool) -> Path:
    secure_elf = cargo_build(ctx, BOARD, debug)

    if nspe == "test":
        non_secure_elf = test_nspe_build.build(ctx, debug=debug)
        nspe_board = test_nspe_build.NON_SECURE_BOARD
    elif nspe == "tock":
        non_secure_elf = tock_kernel_build.build(ctx, app=app, debug=debug)
        nspe_board = tock_kernel_build.NON_SECURE_BOARD
    else:
        raise ValueError(f"Unknown NSPE: {nspe}")

    return merge_secure_non_secure_hex(
        ctx,
        BOARD,
        nspe_board,
        secure_elf,
        non_secure_elf,
        debug,
        [],
    )


@build_task(default=True, help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def build(ctx: Context, nspe="test", app=None, debug=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""
    return _build_merged(ctx, nspe, app, bool(debug))


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def flash(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and flash the secure and non-secure images with probe-rs."""
    merged = _build_merged(ctx, nspe, app, bool(debug))
    return flash_hex(ctx, BOARD, merged)


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def program(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and program the secure image with OpenOCD."""
    merged = _build_merged(ctx, nspe, app, bool(debug))
    return program_hex(ctx, BOARD, merged)


def vscode_build_targets(release: bool = False) -> list[VscodeBuildTarget]:
    profile_short_snake = "_r" if release else "_d"
    build_test_cmd, build_tock_cmd = get_vscode_build_commands(release)
    common_task = vscode_common_build_task()
    
    return [
        {
            **common_task,
            "label": f"build{profile_short_snake}.psc3m5_evk_test",
            "options": {"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            "command": build_test_cmd,
        },
        {
            **common_task,
            "label": f"build{profile_short_snake}.psc3m5_evk_tock",
            "options": {"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            "command": build_tock_cmd,
        },
    ]


def vscode_launch_targets(openocd_path: str, release: bool = False) -> list[VscodeLaunchTarget]:
    profile = "release" if release else "debug"
    profile_short = "(R)" if release else "(D)"
    profile_short_snake = "_r" if release else "_d"
    
    base_conf: VscodeLaunchTarget = {
        "type": "cortex-debug",
        "servertype": "openocd",
        "serverpath": openocd_path, 
        "request": "launch",
        "cwd": "${workspaceFolder}",
        "openOCDLaunchCommands": ["init; reset init;"],
        "svdFile": "${workspaceFolder}/.local/svds/psc3.svd",
        "configFiles": ["${workspaceFolder}/boards/psc3m5_evk/openocd.tcl"],
    }
    
    return [
        {
            "name": f"Test-PSC3 FN {profile_short}",
            **base_conf,
            "executable": f"target/thumbv8m.main-none-eabi/{profile}/test_merged.hex",
            "preLaunchCommands": [
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_test_nspe",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_secure",
            ],
            "preLaunchTask": f"build{profile_short_snake}.psc3m5_evk_test",
        },
        {
            "name": f"Tock-PSC3 FN {profile_short}",
            **base_conf,
            "executable": f"target/thumbv8m.main-none-eabi/{profile}/kernel_merged.hex",
            "preLaunchCommands": [
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_tock_kernel",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_secure",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_tock_app",
            ],
            "preLaunchTask": f"build{profile_short_snake}.psc3m5_evk_tock",
        },
    ]
