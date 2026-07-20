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
    parse_features,
    make_vscode_build_command,
    VscodeLaunchTarget,
    VscodeBuildTarget,
    vscode_common_build_task,
    resolve_openocd,
)
from tools.build.board import (
    BoardConfig,
    Manufacturer,
    flash_hex,
    program_hex,
)
from tools.build.secure_build import build_firmware

from boards.psc3m5_evk.tasks import (
    TOCK_LAYOUT,
    MCUBOOT_SECURE,
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


def _build(ctx, nspe, app, debug, features=None):
    return build_firmware(
        ctx,
        BOARD,
        nspe,
        app,
        debug,
        mcuboot=MCUBOOT_SECURE,
        tock_layout=TOCK_LAYOUT,
        test_nspe_build_module=test_nspe_build,
        tock_kernel_build_module=tock_kernel_build,
        features=features,
    )


@build_task(
    default=True,
    help={
        "nspe": NSPE_HELP,
        "app": APP_HELP,
        "debug": DEBUG_HELP,
        "features": "Comma-separated list of features for tock_psa_app.",
    },
)
def build(
    ctx: Context,
    nspe: str | None = None,
    app=None,
    debug=False,
    features: str | None = None,
):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""
    fl = parse_features(features)
    if nspe is None:
        _build(ctx, "tock", app, bool(debug), fl)
        _build(ctx, "test", app, bool(debug))
        return
    _build(ctx, nspe, app, bool(debug), fl)


@build_task(
    help={
        "nspe": NSPE_HELP,
        "app": APP_HELP,
        "debug": DEBUG_HELP,
        "features": "Comma-separated list of features for tock_psa_app.",
    }
)
def flash(
    ctx: Context,
    nspe="test",
    app=None,
    debug=False,
    features: str | None = None,
):
    """Build, merge, and flash the secure and non-secure images with probe-rs."""
    result = _build(ctx, nspe, app, bool(debug), parse_features(features))
    return flash_hex(ctx, BOARD, result.merged_hex)


@build_task(
    help={
        "nspe": NSPE_HELP,
        "app": APP_HELP,
        "debug": DEBUG_HELP,
        "features": "Comma-separated list of features for tock_psa_app.",
    }
)
def program(
    ctx: Context,
    nspe="test",
    app=None,
    debug=False,
    features: str | None = None,
):
    """Build, merge, and program the secure image with OpenOCD."""
    result = _build(ctx, nspe, app, bool(debug), parse_features(features))
    return program_hex(ctx, BOARD, result.merged_hex)


from boards.psc3m5_evk.tasks import term  # noqa: F401


def vscode_build_targets(release: bool = False) -> list[VscodeBuildTarget]:
    profile_short_snake = "_r" if release else "_d"
    common_task = vscode_common_build_task()

    return [
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_test",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            command=make_vscode_build_command(release, nspe="test"),
        ),
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_tock",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            command=make_vscode_build_command(release, nspe="tock"),
        ),
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_tock_loop_token",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            command=make_vscode_build_command(
                release, nspe="tock", features="test_loop_token"
            ),
        ),
    ]


def vscode_launch_targets(release: bool = False) -> list[VscodeLaunchTarget]:
    openocd_path = str(resolve_openocd(version="infineon"))
    profile = "release" if release else "debug"
    profile_short = "(R)" if release else "(D)"
    profile_short_snake = "_r" if release else "_d"

    base_conf = VscodeLaunchTarget(
        type="cortex-debug",
        servertype="openocd",
        serverpath=openocd_path,
        request="launch",
        cwd="${workspaceFolder}",
        openOCDLaunchCommands=["init; reset init;"],
        svdFile="${workspaceFolder}/.local/svds/psc3.svd",
        configFiles=["${workspaceFolder}/boards/psc3m5_evk/openocd.tcl"],
    )

    return [
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"Test-PSC3 FN {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_test_nspe_merged.hex",
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_test_nspe",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_secure",
            ],
            preLaunchTask=f"build{profile_short_snake}.psc3m5_evk_test",
        ),
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"Tock-PSC3 FN {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_kernel_merged.hex",
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_tock_kernel",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_secure",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/tock_psa_app",
            ],
            preLaunchTask=f"build{profile_short_snake}.psc3m5_evk_tock",
        ),
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"Tock-PSC3 FN Loop Token {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_kernel_merged.hex",
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_tock_kernel",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_secure",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/tock_psa_app",
            ],
            preLaunchTask=f"build{profile_short_snake}.psc3m5_evk_tock_loop_token",
        ),
    ]
