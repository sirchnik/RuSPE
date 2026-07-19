# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations
import sys
from pathlib import Path
from invoke.context import Context
from tools.build.invoke_support import build_task

REPO_ROOT = Path(__file__).resolve().parents[2]


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
