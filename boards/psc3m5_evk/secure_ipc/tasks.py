# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build.invoke_support import (
    BuildError,
    build_task,
    VscodeLaunchTarget,
    VscodeBuildTarget,
    vscode_common_build_task,
    get_vscode_build_commands,
    resolve_openocd,
)
from tools.build.board import (
    BoardConfig,
    Manufacturer,
    cargo_build,
    elf_to_hex,
    flash_hex,
    merge_secure_non_secure_hex,
    program_hex,
)

from boards.psc3m5_evk.services.attest_srv.build import build as build_attest
from boards.psc3m5_evk.services.crypto_srv.build import build as build_crypto
from boards.psc3m5_evk.test_nspe import build as test_nspe_build
from boards.psc3m5_evk.tock.kernel import build as tock_kernel_build

BOARD_DIR = Path(__file__).resolve().parent

BOARD = BoardConfig(
    board_dir=BOARD_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
    crate_name="psc3m5_evk_secure_ipc",
    openocd_tcl=BOARD_DIR.parent / "openocd.tcl",
)

DEBUG_HELP = "Build the debug profile instead of release."
NSPE_HELP = "The Non-Secure Processing Environment to build (test or tock)."
APP_HELP = "Path to a TBF application image (only for tock NSPE)."

BuildEnv = dict[str, str]

ServiceBuilder = Callable[[Context, bool], tuple[Path, BuildEnv]]


@dataclass(frozen=True)
class BuiltService:
    elf_path: Path
    hex_path: Path
    env: BuildEnv


SERVICES: tuple[ServiceBuilder, ...] = (
    build_attest,
    build_crypto,
)


def build_service_hex(
    ctx: Context, service_build: ServiceBuilder, debug: bool
) -> BuiltService:
    service_elf, env = service_build(ctx, debug=debug)
    return BuiltService(
        elf_path=service_elf,
        hex_path=elf_to_hex(
            ctx,
            service_elf,
            service_elf.with_suffix(".hex"),
        ),
        env=env,
    )


def merge_service_envs(services: list[BuiltService]) -> BuildEnv:
    """Merge service environments using indexed keys for multiple services."""
    merged: BuildEnv = {"SERVICE_COUNT": str(len(services))}

    for idx, service in enumerate(services):
        for key, value in service.env.items():
            if key.startswith("SERVICE_"):
                indexed_key = f"{key}_{idx}"
            else:
                indexed_key = key

            if indexed_key in merged:
                if key.startswith("SERVICE_"):
                    raise BuildError(
                        f"Duplicate service index in environment '{indexed_key}': '{merged[indexed_key]}' vs '{value}'"
                    )
                elif merged[indexed_key] != value:
                    raise BuildError(
                        f"Conflicting service environment '{indexed_key}': '{merged[indexed_key]}' vs '{value}'"
                    )
            else:
                merged[indexed_key] = value

    return merged


def _build_merged(ctx: Context, nspe: str, app: str | None, debug: bool) -> Path:
    services = [build_service_hex(ctx, service, debug) for service in SERVICES]
    service_env = merge_service_envs(services)

    secure_elf = cargo_build(ctx, BOARD, debug, env=service_env)

    if nspe == "test":
        non_secure_elf = test_nspe_build.build(ctx, debug=debug)
        nspe_board = test_nspe_build.NON_SECURE_BOARD
    elif nspe == "tock":
        non_secure_elf = tock_kernel_build.build(ctx, app=app, debug=debug)
        nspe_board = tock_kernel_build.NON_SECURE_BOARD
    else:
        raise ValueError(f"Unknown NSPE: {nspe}")

    extra_hexes = [s.hex_path for s in services]

    return merge_secure_non_secure_hex(
        ctx,
        BOARD,
        nspe_board,
        secure_elf,
        non_secure_elf,
        debug,
        extra_hexes,
    )


@build_task(
    default=True, help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP}
)
def build(ctx: Context, nspe="test", app=None, debug=False):
    """Build the secure IPC kernel and selected services, merge with NSPE."""
    return _build_merged(ctx, nspe, app, bool(debug))


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def flash(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and flash the secure IPC and non-secure images with probe-rs."""
    merged = _build_merged(ctx, nspe, app, bool(debug))
    return flash_hex(ctx, BOARD, merged)


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def program(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and program the secure IPC image with OpenOCD."""
    merged = _build_merged(ctx, nspe, app, bool(debug))
    return program_hex(ctx, BOARD, merged)


def vscode_build_targets(release: bool = False) -> list[VscodeBuildTarget]:
    profile_short_snake = "_r" if release else "_d"
    build_test_cmd, build_tock_cmd = get_vscode_build_commands(release)
    common_task = vscode_common_build_task()

    return [
        {
            **common_task,
            "label": f"build{profile_short_snake}.psc3m5_evk_test_ipc",
            "options": {"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure_ipc"},
            "command": build_test_cmd,
        },
        {
            **common_task,
            "label": f"build{profile_short_snake}.psc3m5_evk_tock_ipc",
            "options": {"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure_ipc"},
            "command": build_tock_cmd,
        },
    ]


def vscode_launch_targets(release: bool = False) -> list[VscodeLaunchTarget]:
    openocd_path = str(resolve_openocd(version="infineon"))
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

    service_symbols = []
    for srv in SERVICES:
        module = sys.modules[srv.__module__]
        conf = module.SERVICE_CONF
        service_symbols.append(
            f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{conf.crate_name}"
        )

    return [
        {
            "name": f"Test-PSC3 IPC {profile_short}",
            **base_conf,
            "executable": f"target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_test_nspe_merged.hex",
            "preLaunchCommands": [
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_test_nspe",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_secure_ipc",
            ]
            + service_symbols,
            "preLaunchTask": f"build{profile_short_snake}.psc3m5_evk_test_ipc",
        },
        {
            "name": f"Tock-PSC3 IPC {profile_short}",
            **base_conf,
            "executable": f"target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_kernel_merged.hex",
            "preLaunchCommands": [
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_tock_kernel",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_secure_ipc",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/psc3m5_evk_tock_app",
            ]
            + service_symbols,
            "preLaunchTask": f"build{profile_short_snake}.psc3m5_evk_tock_ipc",
        },
    ]
