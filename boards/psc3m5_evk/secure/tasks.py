# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
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
    resolve_openocd,
    inv_executable,
)
from tools.build.board import (
    BoardConfig,
    Manufacturer,
    cargo_build,
    flash_hex,
    merge_secure_non_secure_hex,
    program_hex,
    elf_to_hex,
)
from tools.build.mcuboot import patch_mcuboot_sig

from boards.psc3m5_evk.test_nspe import build as test_nspe_build
from boards.psc3m5_evk.tock.kernel import build as tock_kernel_build

BOARD_DIR = Path(__file__).resolve().parent

SVD_INFO = (
    "psc3.svd",
    "https://raw.githubusercontent.com/Infineon/mtb-pdl-cat1/refs/heads/master/devices/COMPONENT_CAT1B/svd/psc3.svd",
)

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


def _build_merged(
    ctx: Context,
    nspe: str,
    app: str | None,
    debug: bool,
    features: list[str] | None = None,
) -> Path:
    from integrations.tock.tock_psa_app import build as tock_psa_app_build
    from integrations.tock.tock_interrupt_test_app import (
        build as tock_interrupt_test_app_build,
    )

    secure_elf = cargo_build(ctx, BOARD, debug)

    target_root = BOARD.target_root(debug)
    secure_hex = target_root / f"{BOARD.prefixed_platform}.hex"
    elf_to_hex(ctx, secure_elf, secure_hex)

    patch_mcuboot_sig(
        secure_hex,
        mcuboot_addr=0x3200FF00,
        payload_start=0x32000000,
        payload_end=0x3200FEFF,
    )

    if nspe == "test":
        non_secure_elf = test_nspe_build.build(ctx, debug=debug)
        nspe_board = test_nspe_build.NON_SECURE_BOARD
    elif nspe == "tock":
        if app is None:
            app1_tbf = tock_psa_app_build.build(
                ctx,
                board="psc3m5",
                flash_start="0x22036000",
                flash_length="0x3000",
                ram_start="0x2400A000",
                ram_length="0x3000",
                debug=debug,
                features=features,
            )
            app2_tbf = tock_interrupt_test_app_build.build(
                ctx,
                flash_start="0x2203A000",
                flash_length="0x3000",
                ram_start="0x2400D000",
                ram_length="0x3000",
                debug=debug,
            )
            from tools.build.board import combine_tock_apps

            app_path = combine_tock_apps(app1_tbf, app2_tbf, pad_len=0x4000)
        else:
            app_path = Path(app)
        non_secure_elf = tock_kernel_build.build(ctx, app=app_path, debug=debug)
        nspe_board = tock_kernel_build.NON_SECURE_BOARD
    else:
        raise ValueError(f"Unknown NSPE: {nspe}")

    return merge_secure_non_secure_hex(
        ctx,
        BOARD,
        nspe_board,
        secure_hex,
        non_secure_elf,
        debug,
        [],
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
    features_list = [f.strip() for f in features.split(",")] if features else None
    if nspe is None:
        _build_merged(ctx, "tock", app, bool(debug), features=features_list)
        _build_merged(ctx, "test", app, bool(debug))
        return
    _build_merged(ctx, nspe, app, bool(debug), features=features_list)


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
    features_list = [f.strip() for f in features.split(",")] if features else None
    merged = _build_merged(ctx, nspe, app, bool(debug), features=features_list)
    return flash_hex(ctx, BOARD, merged)


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
    features_list = [f.strip() for f in features.split(",")] if features else None
    merged = _build_merged(ctx, nspe, app, bool(debug), features=features_list)
    return program_hex(ctx, BOARD, merged)


from boards.psc3m5_evk.common_tasks import term  # noqa: F401


def vscode_build_targets(release: bool = False) -> list[VscodeBuildTarget]:
    profile_short_snake = "_r" if release else "_d"
    build_test_cmd, build_tock_cmd = get_vscode_build_commands(release)
    common_task = vscode_common_build_task()

    inv_exec = inv_executable()
    debug_arg = "" if release else " --debug"
    if os.name == "nt":
        build_tock_loop_token_cmd = f'& "{inv_exec}" build{debug_arg} --nspe=tock --features=test_loop_token'
    else:
        build_tock_loop_token_cmd = f'"{inv_exec}" build{debug_arg} --nspe=tock --features=test_loop_token'

    return [
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_test",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            command=build_test_cmd,
        ),
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_tock",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            command=build_tock_cmd,
        ),
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_tock_loop_token",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure"},
            command=build_tock_loop_token_cmd,
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
