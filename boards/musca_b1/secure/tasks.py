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
    VscodeLaunchTarget,
    VscodeBuildTarget,
    vscode_common_build_task,
    get_vscode_build_commands,
)
from tools.build.board import (
    BoardConfig,
    Manufacturer,
    cargo_build,
    merge_secure_non_secure_hex,
)

from boards.musca_b1.test_nspe import build as test_nspe_build

BOARD_DIR = Path(__file__).resolve().parent

SECURE_BOARD = BoardConfig(
    board_dir=BOARD_DIR,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.OTHER,
    chip="musca_b1",
    crate_name="musca_b1_secure",
)

QEMU_MACHINE = "musca-b1"
QEMU_CPU = "cortex-m33"

DEBUG_HELP = "Build the debug profile instead of release."
NSPE_HELP = "The Non-Secure Processing Environment to build (test or tock)."
APP_HELP = "Path to a TBF application image (only for tock NSPE)."


def _generate_stub_elf(target_dir: Path) -> Path:
    stub_elf = target_dir / "stub.elf"
    if not stub_elf.exists():
        stub_rs = target_dir / "stub.rs"
        stub_rs.write_text(
            "#![no_std]\n#![no_main]\n"
            "#[panic_handler]\nfn panic(_: &core::panic::PanicInfo) -> ! { loop {} }\n"
            '#[no_mangle]\npub extern "C" fn _start() -> ! { loop {} }\n'
        )
        run_command(
            [
                "rustc",
                "--target",
                "thumbv8m.main-none-eabi",
                str(stub_rs),
                "-o",
                str(stub_elf),
            ]
        )
        stub_rs.unlink()
    return stub_elf


def _build_merged(
    ctx: Context, nspe: str, app: str | None, debug: bool
) -> tuple[Path, Path, Path]:
    secure_elf = cargo_build(ctx, SECURE_BOARD, debug)
    _generate_stub_elf(secure_elf.parent)

    if nspe == "test":
        non_secure_elf = test_nspe_build.build(ctx, debug=debug)
        nspe_board = test_nspe_build.NON_SECURE_BOARD
    else:
        raise ValueError(f"Unknown NSPE: {nspe}")

    merged_hex = merge_secure_non_secure_hex(
        ctx,
        SECURE_BOARD,
        nspe_board,
        secure_elf,
        non_secure_elf,
        debug,
        [],
    )
    print(merged_hex)
    return secure_elf, non_secure_elf, merged_hex


@build_task(
    default=True, help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP}
)
def build(ctx: Context, nspe="test", app=None, debug=False):
    """Build the secure image, merge it with the non-secure kernel, and write a HEX output."""
    _, _, merged_hex = _build_merged(ctx, nspe, app, bool(debug))
    return merged_hex


def _run_qemu(secure_elf: Path, non_secure_elf: Path, gdb_listen: bool = False):
    cmd = [
        "qemu-system-arm",
        "-machine",
        QEMU_MACHINE,
        "-cpu",
        QEMU_CPU,
        "-nographic",
        "-semihosting",
        "-kernel",
        str(secure_elf),
        "-device",
        f"loader,file={non_secure_elf}",
    ]
    if gdb_listen:
        cmd.extend(["-S", "-gdb", "tcp::1234"])

    run_command(cmd, cwd=SECURE_BOARD.board_dir)


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def qemu(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and run the images in QEMU."""
    secure_elf, non_secure_elf, _ = _build_merged(ctx, nspe, app, bool(debug))
    _run_qemu(secure_elf, non_secure_elf, gdb_listen=False)


@build_task(help={"nspe": NSPE_HELP, "app": APP_HELP, "debug": DEBUG_HELP})
def qemu_gdb_listen(ctx: Context, nspe="test", app=None, debug=False):
    """Build, merge, and run QEMU, waiting for a GDB connection."""
    secure_elf, non_secure_elf, _ = _build_merged(ctx, nspe, app, bool(debug))
    _run_qemu(secure_elf, non_secure_elf, gdb_listen=True)


def vscode_build_targets(release: bool = False) -> list[VscodeBuildTarget]:
    profile_short_snake = "_r" if release else "_d"
    build_test_cmd, build_tock_cmd = get_vscode_build_commands(release)
    common_task = vscode_common_build_task()

    return [
        {
            **common_task,
            "label": f"build{profile_short_snake}.musca_b1_test",
            "options": {"cwd": "${workspaceFolder}/boards/musca_b1/secure"},
            "command": build_test_cmd,
        },
        {
            **common_task,
            "label": f"build{profile_short_snake}.musca_b1_tock",
            "options": {"cwd": "${workspaceFolder}/boards/musca_b1/secure"},
            "command": build_tock_cmd,
        },
    ]


def vscode_launch_targets(release: bool = False) -> list[VscodeLaunchTarget]:
    profile = "release" if release else "debug"
    profile_short = "(R)" if release else "(D)"
    profile_short_snake = "_r" if release else "_d"

    base_conf: VscodeLaunchTarget = {
        "type": "cortex-debug",
        "servertype": "qemu",
        "serverpath": "qemu-system-arm",
        "request": "launch",
        "cwd": "${workspaceFolder}",
        "cpu": QEMU_CPU,
        "machine": QEMU_MACHINE,
    }

    return [
        {
            "name": f"Musca-B1 Test {profile_short}",
            **base_conf,
            "executable": f"target/thumbv8m.main-none-eabi/{profile}/stub.elf",
            "serverArgs": [
                # "-serial",
                # "stdio",
                "-monitor",
                "none",
                "-serial",
                "stdio",
                "-serial",
                "telnet:127.0.0.1:4321,server,nowait",
                "-device",
                f"loader,file=target/thumbv8m.main-none-eabi/{profile}/musca_b1_test_nspe_merged.hex,addr=0x10000000",
            ],
            "preLaunchCommands": [
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/musca_b1_secure",
                f"add-symbol-file target/thumbv8m.main-none-eabi/{profile}/musca_b1_test_nspe",
            ],
            "preLaunchTask": f"build{profile_short_snake}.musca_b1_test",
        },
    ]
