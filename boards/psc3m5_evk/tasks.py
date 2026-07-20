# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Shared configuration for all psc3m5_evk board variants."""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BOARD_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from invoke.context import Context

from tools.build.invoke_support import build_task, run_command, resolve_openocd
from tools.build.secure_build import McubootConfig
from tools.build.tock_app import TockAppsLayout, TockAppSlot

### Tock app memory layout (shared by secure and secure_ipc)

TOCK_LAYOUT = TockAppsLayout(
    board="psc3m5",
    psa_app=TockAppSlot("0x22036000", "0x3000", "0x2400A000", "0x3000"),
    interrupt_test_app=TockAppSlot("0x2203A000", "0x3000", "0x2400D000", "0x3000"),
)

### MCUboot signing configs

MCUBOOT_SECURE = McubootConfig(
    mcuboot_addr=0x3200FF00,
    payload_start=0x32000000,
    payload_end=0x3200FEFF,
)

MCUBOOT_SECURE_IPC = McubootConfig(
    mcuboot_addr=0x32007F00,
    payload_start=0x32000000,
    payload_end=0x32007EFF,
)

### SVD

SVD_INFO = (
    "psc3.svd",
    "https://raw.githubusercontent.com/Infineon/mtb-pdl-cat1/refs/heads/master/devices/COMPONENT_CAT1B/svd/psc3.svd",
)

### Common invoke tasks


@build_task(
    help={"secure_port": "Optional serial port for secure terminal instead of binho."}
)
def term(ctx: Context, secure_port=None):
    """Open a split terminal for secure and non-secure logging."""
    from tools.debugging.term import launch_split, get_cypress_port

    non_secure_cmd = (
        f"{sys.executable} -m serial.tools.miniterm {get_cypress_port()} 115200"
    )

    if secure_port:
        secure_cmd = f"{sys.executable} -m serial.tools.miniterm {secure_port} 115200"
    else:
        binho_script = str(REPO_ROOT / "tools" / "debugging" / "binho_uart.py")
        secure_cmd = f"{sys.executable} {binho_script}"

    launch_split(non_secure_cmd, secure_cmd)


def _resolve_tool(tool_name: str) -> str:
    python_dir = Path(sys.executable).parent
    tool_path = python_dir / tool_name
    if tool_path.exists():
        return str(tool_path)
    if os.name == "nt":
        tool_path_exe = python_dir / f"{tool_name}.exe"
        if tool_path_exe.exists():
            return str(tool_path_exe)
    return tool_name


@build_task
def provision(ctx: Context):
    """Provision the device with the protection context configuration using edgeprotecttools."""
    tools_dir = BOARD_DIR / "edgeprotecttools"
    config_file = tools_dir / ".edgeprotecttools"
    edgeprotecttools = _resolve_tool("edgeprotecttools")

    if not config_file.exists():
        print("Initializing edgeprotecttools workspace...")
        run_command([edgeprotecttools, "-t", "psoc_c3", "init"], cwd=tools_dir)
    else:
        print("edgeprotecttools already initialized.")

    print("Provisioning device...")
    run_command(
        [
            edgeprotecttools,
            "-t",
            "psoc_c3",
            "provision-device",
            "-p",
            "ns_policy/policy_oem_provisioning.json",
        ],
        cwd=tools_dir,
    )


@build_task
def erase(ctx: Context):
    """Erase the flash on the device using OpenOCD."""
    openocd = resolve_openocd(version="infineon")
    cmd = [str(openocd)]

    openocd_root = os.environ.get("OPENOCD_ROOT")
    if openocd_root:
        cmd.extend(["-s", str(Path(openocd_root) / "scripts")])
    else:
        mtb_path = Path("/opt/ModusToolboxProgtools-1.7/openocd/scripts")
        if mtb_path.exists():
            cmd.extend(["-s", str(mtb_path)])

    cmd.extend(
        [
            "-f",
            "interface/kitprog3.cfg",
            "-c",
            "set ENABLE_ACQUIRE 0",
            "-f",
            "target/infineon/psc3.cfg",
            "-c",
            "init; reset init; erase_all; shutdown",
        ]
    )
    run_command(cmd, cwd=BOARD_DIR)
