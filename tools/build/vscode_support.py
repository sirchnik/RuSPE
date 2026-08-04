# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class VscodeLaunchTarget:
    name: str | None = None
    type: str | None = None
    request: str | None = None
    cwd: str | None = None
    executable: str | None = None
    servertype: str | None = None
    serverpath: str | None = None
    openOCDLaunchCommands: list[str] | None = None
    svdFile: str | None = None
    configFiles: list[str] | None = None
    preLaunchCommands: list[str] | None = None
    preLaunchTask: str | None = None
    cpu: str | None = None
    machine: str | None = None
    serverArgs: list[str] | None = None
    # External GDB server fields (servertype="external")
    gdbTarget: str | None = None
    gdbPath: str | None = None
    objdumpPath: str | None = None
    loadFiles: list[str] | None = None
    symbolFiles: list[dict] | None = None
    showDevDebugOutput: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class VscodeBuildTarget:
    type: str | None = None
    args: list[str] | None = None
    presentation: dict[str, object] | None = None
    group: str | None = None
    label: str | None = None
    options: dict[str, object] | None = None
    isBackground: bool | None = None
    problemMatcher: dict | list | None = None
    dependsOrder: str | None = None
    dependsOn: list[str] | None = None
    command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def inv_executable() -> str:
    if os.name == "nt":
        return "${workspaceFolder}\\.venv\\Scripts\\inv.exe"
    return "${workspaceFolder}/.venv/bin/inv"


def vscode_common_build_task() -> VscodeBuildTarget:
    return VscodeBuildTarget(
        type="shell",
        args=[],
        presentation={"reveal": "silent"},
        group="build",
    )


def get_vscode_build_commands(release: bool = False) -> tuple[str, str]:
    """Return (test_cmd, tock_cmd) build commands - kept for backwards compat."""
    return (
        make_vscode_build_command(release, nspe="test"),
        make_vscode_build_command(release, nspe="tock"),
    )


def make_vscode_build_command(
    release: bool, nspe: str, features: str | None = None
) -> str:
    """Generate a VSCode shell command string for ``inv build --nspe=...``."""
    inv_exec = inv_executable()
    debug_arg = "" if release else " --debug"
    extra = f" --features={features}" if features else ""
    cmd = f'"{inv_exec}" build{debug_arg} --nspe={nspe}{extra}'
    if os.name == "nt":
        cmd = "& " + cmd
    return cmd
