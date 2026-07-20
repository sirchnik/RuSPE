# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Shared configuration for the musca_b1 board."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from invoke.context import Context

from tools.build.invoke_support import build_task
from tools.build.secure_build import McubootConfig
from tools.build.tock_app import TockAppsLayout, TockAppSlot

### Tock app memory layout

TOCK_LAYOUT = TockAppsLayout(
    board="musca_b1",
    psa_app=TockAppSlot("0x00182000", "0x4000", "0x20035000", "0x2000"),
    interrupt_test_app=TockAppSlot("0x00186000", "0x4000", "0x20037000", "0x2000"),
)

### MCUboot signing config

MCUBOOT = McubootConfig(
    mcuboot_addr=0x100FFF00,
    payload_start=0x10000000,
    payload_end=0x100FFEFF,
)

### SVD

SVD_INFO = (
    "musca_b1.svd",
    "https://raw.githubusercontent.com/driveraid/muscab1-pac/refs/heads/master/svd/Musca_B1.svd",
)

### QEMU

QEMU_MACHINE = "musca-b1"
QEMU_CPU = "cortex-m33"


@build_task(help={})
def term(ctx: Context):
    """Open a split terminal for secure and non-secure logging."""
    from tools.debugging.term import launch_split
    import shutil

    telnet = next((cmd for cmd in ("telnet", "nc") if shutil.which(cmd)), None)

    if not telnet:
        raise RuntimeError("No telnet or nc found!")

    launch_split(f"{telnet} 127.0.0.1 4321", f"{telnet} 127.0.0.1 4322")
