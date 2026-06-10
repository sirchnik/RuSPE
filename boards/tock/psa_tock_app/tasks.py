# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

from dataclasses import dataclass
import sys
from pathlib import Path

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build.invoke_support import (
    BuildError,
    build_task,
    run_command,
    resolve_cmd,
)


@dataclass(frozen=True)
class AppConfig:
    repo_root: Path
    app_dir: Path
    flash_start: str
    flash_length: str
    ram_start: str
    ram_length: str
    app_name: str

    def build_type(self, debug: bool) -> str:
        return "debug" if debug else "release"

    def target_root(self, debug: bool) -> Path:
        return (
            self.repo_root
            / "target"
            / "thumbv8m.main-none-eabi"
            / self.build_type(debug)
        )

    def elf_image(self, debug: bool) -> Path:
        return self.target_root(debug) / self.app_name

    def tbf_image(self, debug: bool) -> Path:
        return self.target_root(debug) / f"{self.app_name}.tbf"

    def linker_env(self) -> dict[str, str]:
        return {
            "LIBTOCK_LINKER_FLASH": self.flash_start,
            "LIBTOCK_LINKER_FLASH_LENGTH": self.flash_length,
            "LIBTOCK_LINKER_RAM": self.ram_start,
            "LIBTOCK_LINKER_RAM_LENGTH": self.ram_length,
        }


def cargo_build_app(ctx: Context, app: AppConfig, debug: bool) -> Path:
    command = ["cargo", "build"]
    if not debug:
        command.append("--release")
    run_command(command, cwd=app.app_dir, env=app.linker_env())
    return app.elf_image(debug)


def elf_to_tbf(ctx: Context, app: AppConfig, debug: bool) -> Path:
    elf = cargo_build_app(ctx, app, debug)
    if not elf.exists():
        raise BuildError(f"App ELF does not exist: {elf}")

    tbf = app.tbf_image(debug)
    tab = tbf.with_suffix(".tab")
    elf2tab = resolve_cmd("elf2tab")
    if elf2tab is None:
        raise BuildError("elf2tab tool not found in PATH")
    run_command(
        [
            str(elf2tab),
            "--kernel-major",
            "2",
            "--kernel-minor",
            "1",
            "-n",
            app.app_name,
            "-o",
            str(tab),
            "--stack",
            "4096",
            "--minimum-footer-size",
            "256",
            str(elf),
        ],
        cwd=app.app_dir,
    )

    if not tbf.exists():
        raise BuildError(f"elf2tab did not produce expected TBF file: {tbf}")

    return tbf


APP_DIR = Path(__file__).resolve().parent

APP = AppConfig(
    repo_root=REPO_ROOT,
    app_dir=APP_DIR,
    flash_start="0x22036000",
    flash_length="0x3000",
    ram_start="0x2400A000",
    ram_length="0x3000",
    app_name="psa_tock_app",
)

DEBUG_HELP = "Build the debug profile instead of release."


@build_task(default=True, help={"debug": DEBUG_HELP})
def build(ctx: Context, debug=False):
    """Build the Tock userland app and convert it to TBF."""

    return elf_to_tbf(ctx, APP, bool(debug))
