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
    elf_to_hex,
    flash_hex,
    program_hex,
    resolve_gdb,
    is_port_in_use,
)
from tools.build.naming import get_merged_ipc_hex_filename, get_psa_app_filename
from tools.build.secure_build import build_firmware

from boards.psc3m5_evk.tasks import (
    TOCK_LAYOUT,
    MCUBOOT_SECURE_IPC,
)
from boards.psc3m5_evk.services.attest_srv.build import build as build_attest
from boards.psc3m5_evk.services.crypto_srv.build import build as build_crypto
from boards.psc3m5_evk.test_nspe import build as test_nspe_build
from boards.psc3m5_evk.tock.kernel import build as tock_kernel_build
from tools.generate.generate_service import generate_service_crate

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
    service_elf, env = service_build(ctx, debug)
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


def _build(ctx, nspe, app, debug, features=None):
    services = [build_service_hex(ctx, s, debug) for s in SERVICES]
    return build_firmware(
        ctx,
        BOARD,
        nspe,
        app,
        debug,
        mcuboot=MCUBOOT_SECURE_IPC,
        tock_layout=TOCK_LAYOUT,
        test_nspe_build_module=test_nspe_build,
        tock_kernel_build_module=tock_kernel_build,
        features=features,
        cargo_env=merge_service_envs(services),
        extra_hexes=[s.hex_path for s in services],
    )


@build_task(help={"force": "Overwrite existing generated code if they already exist."})
def generate(ctx: Context, force=False):
    """Generate all services defined in the local service catalog."""
    from .service_catalog import CATALOG

    for name, spec in CATALOG.items():
        if spec.mode == "generated":
            print(f"Generating service '{spec.name}' at {spec.service_dir}")
            generate_service_crate(REPO_ROOT, spec, force=force)
    print("Done generating services.")


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
    """Build the secure IPC kernel and selected services, merge with NSPE."""
    fl = parse_features(features)
    if nspe is None:
        _build(ctx, "tock", app, bool(debug), fl)
        _build(ctx, "test", app, bool(debug))
        return
    return _build(ctx, nspe, app, bool(debug), fl)


@build_task(
    help={
        "nspe": NSPE_HELP,
        "app": APP_HELP,
        "debug": DEBUG_HELP,
        "features": "Comma-separated list of features for tock_psa_app.",
        "openocd": "Use OpenOCD for programming instead of probe-rs.",
    }
)
def flash(
    ctx: Context,
    nspe="test",
    app=None,
    debug=False,
    features: str | None = None,
    openocd: bool = False,
):
    """Build, merge, and flash the secure IPC and non-secure images (probe-rs by default, OpenOCD with --openocd)."""
    result = _build(ctx, nspe, app, bool(debug), parse_features(features))
    if openocd:
        return program_hex(ctx, BOARD, result.merged_hex)
    return flash_hex(ctx, BOARD, result.merged_hex)


@build_task(
    help={
        "nspe": NSPE_HELP,
        "app": APP_HELP,
        "debug": DEBUG_HELP,
        "features": "Comma-separated list of features for tock_psa_app.",
    }
)
def trace(
    ctx: Context,
    nspe="test",
    app=None,
    debug=False,
    features: str | None = None,
):
    """Run automated GDB performance trace."""
    import subprocess
    import time

    result = _build(ctx, nspe, app, bool(debug), parse_features(features))

    openocd = resolve_openocd(version="infineon")
    gdb = resolve_gdb()

    # Kill any lingering OpenOCD instances to prevent connection issues
    subprocess.run(["pkill", "-x", "openocd"], stderr=subprocess.DEVNULL)
    time.sleep(0.1)

    if not is_port_in_use(3333):
        print("Starting OpenOCD in the background...")
        openocd_cmd = [str(openocd), "-f", str(BOARD.openocd_tcl)]
        openocd_process = subprocess.Popen(
            openocd_cmd,
            cwd=BOARD.board_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            if is_port_in_use(3333):
                break
            time.sleep(0.1)
        else:
            openocd_process.kill()
            raise BuildError("OpenOCD failed to start or bind to port 3333.")
    else:
        print("OpenOCD is already running on port 3333, connecting to it...")
        openocd_process = None

    try:
        script_path = REPO_ROOT / "tools" / "debugging" / "gdb_trace_auto.py"
        gdb_args = [str(gdb), "-x", str(script_path), str(result.secure_elf)]
        subprocess.run(gdb_args, cwd=BOARD.board_dir)
    finally:
        if openocd_process:
            print("Cleaning up OpenOCD...")
            openocd_process.terminate()
            openocd_process.wait()


from boards.psc3m5_evk.tasks import term  # noqa: F401


def vscode_build_targets(release: bool = False) -> list[VscodeBuildTarget]:
    profile_short_snake = "_r" if release else "_d"
    common_task = vscode_common_build_task()

    return [
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_test_ipc",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure_ipc"},
            command=make_vscode_build_command(release, nspe="test"),
        ),
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_tock_ipc",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure_ipc"},
            command=make_vscode_build_command(release, nspe="tock"),
        ),
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.psc3m5_evk_tock_ipc_loop_token",
            options={"cwd": "${workspaceFolder}/boards/psc3m5_evk/secure_ipc"},
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

    service_symbols = []
    for srv in SERVICES:
        module = sys.modules[srv.__module__]
        conf = module.SERVICE_CONF
        service_symbols.append(
            f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{conf.crate_name}"
        )

    return [
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"Test-PSC3 IPC {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/{get_merged_ipc_hex_filename(BOARD, test_nspe_build.NON_SECURE_BOARD)}",
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{test_nspe_build.NON_SECURE_BOARD.crate_name}",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{BOARD.crate_name}",
            ]
            + service_symbols,
            preLaunchTask=f"build{profile_short_snake}.psc3m5_evk_test_ipc",
        ),
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"Tock-PSC3 IPC {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/{get_merged_ipc_hex_filename(BOARD, tock_kernel_build.NON_SECURE_BOARD, has_apps=True)}",
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{tock_kernel_build.NON_SECURE_BOARD.crate_name}",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{BOARD.crate_name}",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{get_psa_app_filename(BOARD.board_name)}",
            ]
            + service_symbols,
            preLaunchTask=f"build{profile_short_snake}.psc3m5_evk_tock_ipc",
        ),
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"Tock-PSC3 IPC Loop Token {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/{get_merged_ipc_hex_filename(BOARD, tock_kernel_build.NON_SECURE_BOARD, has_apps=True)}",
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{tock_kernel_build.NON_SECURE_BOARD.crate_name}",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{BOARD.crate_name}",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/{get_psa_app_filename(BOARD.board_name)}",
            ]
            + service_symbols,
            preLaunchTask=f"build{profile_short_snake}.psc3m5_evk_tock_ipc_loop_token",
        ),
    ]
