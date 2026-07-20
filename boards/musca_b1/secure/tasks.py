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
    run_command,
    make_vscode_build_command,
    VscodeLaunchTarget,
    VscodeBuildTarget,
    vscode_common_build_task,
)
from tools.build.board import (
    BoardConfig,
    Manufacturer,
)
from tools.build.secure_build import FirmwareResult, build_firmware

from boards.musca_b1.tasks import (
    TOCK_LAYOUT,
    MCUBOOT,
    QEMU_MACHINE,
    QEMU_CPU,
)
from boards.musca_b1.test_nspe import build as test_nspe_build
from boards.musca_b1.tock.kernel import build as tock_kernel_build

BOARD_DIR = Path(__file__).resolve().parent

SECURE_BOARD = BoardConfig(
    board_dir=BOARD_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.OTHER,
    chip="musca_b1",
    crate_name="musca_b1_secure",
)

DEBUG_HELP = "Build the debug profile instead of release."
NSPE_HELP = "The Non-Secure Processing Environment to build (test or tock)."
APP_HELP = "Path to a TBF application image (only for tock NSPE)."


def _build(ctx, nspe, app, debug):
    return build_firmware(
        ctx,
        SECURE_BOARD,
        nspe,
        app,
        debug,
        mcuboot=MCUBOOT,
        tock_layout=TOCK_LAYOUT,
        test_nspe_build_module=test_nspe_build,
        tock_kernel_build_module=tock_kernel_build,
        extract_mcuboot_sig=True,
    )


@build_task(
    default=True, help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP}
)
def build(ctx: Context, nspe: str | None = None, app=None, debug=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""
    if nspe is None:
        # WIP
        # _build(ctx, "tock", app, bool(debug))
        result = _build(ctx, "test", app, bool(debug))
        return result.merged_hex
    result = _build(ctx, nspe, app, bool(debug))
    return result.merged_hex


### QEMU


def get_qemu_cmd(
    result: FirmwareResult,
    gdb_listen: bool = False,
    telnet_port: int | None = None,
    telnet_wait: bool = False,
) -> list[str]:
    cmd = [
        "qemu-system-arm",
        "-machine",
        QEMU_MACHINE,
        "-cpu",
        QEMU_CPU,
        "-semihosting",
        "-kernel",
        str(result.secure_elf),
    ]

    if result.tock_noapps_bin and result.tock_noapps_bin.exists():
        cmd.extend(["-device", f"loader,file={result.tock_noapps_bin},addr=0x00102000"])
        if result.tock_apps_tbf and result.tock_apps_tbf.exists():
            cmd.extend(
                ["-device", f"loader,file={result.tock_apps_tbf},addr=0x00182000"]
            )
    else:
        cmd.extend(["-device", f"loader,file={result.non_secure_elf}"])

    if telnet_port is not None:
        # Run QEMU headless when exposing a telnet serial port to avoid
        # gtk/SDL display initialization on CI runners.
        cmd.extend(
            [
                "-display",
                "none",
                "-monitor",
                "none",
                "-serial",
                "telnet:127.0.0.1:4322,server,nowait",
            ]
        )
        if telnet_wait:
            cmd.extend(["-serial", f"telnet:127.0.0.1:{telnet_port},server"])
        else:
            cmd.extend(["-serial", f"telnet:127.0.0.1:{telnet_port},server,nowait"])
    else:
        cmd.append("-nographic")

    if result.mcuboot_sig_bin and result.mcuboot_sig_bin.exists():
        cmd.extend(
            [
                "-device",
                f"loader,file={result.mcuboot_sig_bin},addr={hex(MCUBOOT.mcuboot_addr)}",
            ]
        )
    if gdb_listen:
        cmd.extend(["-S", "-gdb", "tcp::1234"])

    return cmd


def _run_qemu(result: FirmwareResult, gdb_listen: bool = False):
    cmd = get_qemu_cmd(result, gdb_listen=gdb_listen)
    run_command(cmd, cwd=SECURE_BOARD.board_dir)


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def qemu(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and run the images in QEMU."""
    result = _build(ctx, nspe, app, bool(debug))
    _run_qemu(result, gdb_listen=False)


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def qemu_gdb_listen(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and run QEMU, waiting for a GDB connection."""
    result = _build(ctx, nspe, app, bool(debug))
    _run_qemu(result, gdb_listen=True)


from boards.musca_b1.tasks import term  # noqa: F401

### VSCode


def vscode_build_targets(release: bool = False) -> list[VscodeBuildTarget]:
    profile_short_snake = "_r" if release else "_d"
    common_task = vscode_common_build_task()

    return [
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.musca_b1_test",
            options={"cwd": "${workspaceFolder}/boards/musca_b1/secure"},
            command=make_vscode_build_command(release, nspe="test"),
        ),
        VscodeBuildTarget(
            **common_task.to_dict(),
            label=f"build{profile_short_snake}.musca_b1_tock",
            options={"cwd": "${workspaceFolder}/boards/musca_b1/secure"},
            command=make_vscode_build_command(release, nspe="tock"),
        ),
    ]


def vscode_launch_targets(release: bool = False) -> list[VscodeLaunchTarget]:
    profile = "release" if release else "debug"
    profile_short = "(R)" if release else "(D)"
    profile_short_snake = "_r" if release else "_d"

    base_conf = VscodeLaunchTarget(
        type="cortex-debug",
        servertype="qemu",
        serverpath="qemu-system-arm",
        request="launch",
        cwd="${workspaceFolder}",
        cpu=QEMU_CPU,
        machine=QEMU_MACHINE,
        svdFile="${workspaceFolder}/.local/svds/musca_b1.svd",
    )

    return [
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"Musca-B1 Test {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/musca_b1_secure",
            serverArgs=[
                # "-serial",
                # "stdio",
                "-monitor",
                "none",
                "-serial",
                "telnet:127.0.0.1:4322,server,nowait",
                "-serial",
                "telnet:127.0.0.1:4321,server,nowait",
                "-device",
                f"loader,file=target/thumbv8m.main-none-eabi/{profile}/musca_b1_test_nspe",
                "-device",
                f"loader,file=target/thumbv8m.main-none-eabi/{profile}/musca_b1_secure_mcuboot_sig.bin,addr=0x100FFF00",
            ],
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/musca_b1_test_nspe",
            ],
            preLaunchTask=f"build{profile_short_snake}.musca_b1_test",
        ),
        VscodeLaunchTarget(
            **base_conf.to_dict(),
            name=f"[WIP] Musca-B1 Tock {profile_short}",
            executable=f"target/thumbv8m.main-none-eabi/{profile}/musca_b1_secure",
            serverArgs=[
                "-monitor",
                "none",
                "-serial",
                "telnet:127.0.0.1:4322,server,nowait",
                "-serial",
                "telnet:127.0.0.1:4321,server,nowait",
                "-device",
                f"loader,file=target/thumbv8m.main-none-eabi/{profile}/musca_b1_kernel-noapps.bin,addr=0x00102000",
                "-device",
                f"loader,file=target/thumbv8m.main-none-eabi/{profile}/combined_apps.tbf,addr=0x00182000",
                "-device",
                f"loader,file=target/thumbv8m.main-none-eabi/{profile}/musca_b1_secure_mcuboot_sig.bin,addr=0x100FFF00",
            ],
            preLaunchCommands=[
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/musca_b1_kernel-app.elf",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/tock_psa_app",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/tock_interrupt_test_app",
            ],
            preLaunchTask=f"build{profile_short_snake}.musca_b1_tock",
        ),
    ]
