from __future__ import annotations

from dataclasses import dataclass
import sys
from pathlib import Path

from invoke.context import Context
from invoke.tasks import task

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.invoke_support import (  # noqa: E402
    BuildError,
    _command_path,
    handle_build_errors,
    run_command,
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


def resolve_elf2tab() -> Path | None:
    return _command_path("elf2tab")


def cargo_build_app(ctx: Context, app: AppConfig, debug: bool) -> Path:
    command = ["cargo", "build"]
    if not debug:
        command.append("--release")
    run_command(ctx, command, cwd=app.app_dir, extra_env=app.linker_env())
    return app.elf_image(debug)


def elf_to_tbf(ctx: Context, app: AppConfig, debug: bool) -> Path:
    elf = cargo_build_app(ctx, app, debug)
    if not elf.exists():
        raise BuildError(f"App ELF does not exist: {elf}")

    elf2tab = resolve_elf2tab()
    if elf2tab is None:
        raise BuildError(
            "Required tool not found: elf2tab. Install with 'cargo install elf2tab'."
        )

    tbf = app.tbf_image(debug)
    tab = tbf.with_suffix(".tab")
    run_command(
        ctx,
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
    flash_start="0x22032000",
    flash_length="0xA000",
    ram_start="0x24008000",
    ram_length="0x5800",
    app_name="psa_tock_app",
)

DEBUG_HELP = "Build the debug profile instead of release."


@task(help={"debug": DEBUG_HELP})
@handle_build_errors
def build(ctx, debug=False):
    """Build the Tock userland app ELF."""

    return cargo_build_app(ctx, APP, bool(debug))


@task(default=True, help={"debug": DEBUG_HELP})
@handle_build_errors
def tbf(ctx, debug=False):
    """Build the Tock userland app and convert it to TBF."""

    return elf_to_tbf(ctx, APP, bool(debug))
