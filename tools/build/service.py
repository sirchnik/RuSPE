# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from invoke.context import Context

from tools.build.invoke_support import BuildError, run_command


@dataclass(frozen=True)
class ServiceConfig:
    repo_root: Path
    service_dir: Path
    flash_origin: str = "0x32010000"
    flash_length: str = "0x3F00"
    ram_origin: str = "0x34002F00"
    ram_length: str = "0x1100"

    @property
    def service(self) -> str:
        return self.service_dir.name

    def linker_env(self) -> dict[str, str]:
        """Return environment variables for linker script generation.
        
        Used by cargo build scripts (e.g. attest/build.rs) to generate
        the concrete linker script with configured memory regions.
        """
        return {
            "SERVICE_FLASH_ORIGIN": self.flash_origin,
            "SERVICE_FLASH_LENGTH": self.flash_length,
            "SERVICE_RAM_ORIGIN": self.ram_origin,
            "SERVICE_RAM_LENGTH": self.ram_length,
        }


def _cargo_package_name(crate_dir: Path) -> str:
    cargo_toml = crate_dir / "Cargo.toml"
    if not cargo_toml.exists():
        return crate_dir.name

    try:
        data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
        package = data.get("package", {})
        name = package.get("name")
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass

    return crate_dir.name


def _candidate_artifacts(target_dir: Path, build_type: str, binary_name: str) -> list[Path]:
    names = [binary_name]
    underscored = binary_name.replace("-", "_")
    if underscored != binary_name:
        names.append(underscored)

    candidates: list[Path] = []
    for name in names:
        candidates.extend(
            [
                target_dir / "thumbv8m.main-none-eabi" / build_type / name,
                target_dir / "thumbv8m.main-none-eabi" / build_type / f"{name}.elf",
                target_dir / build_type / name,
                target_dir / build_type / f"{name}.elf",
                target_dir / build_type / f"{name}.exe",
            ]
        )
    return candidates


def _resolve_cargo_artifact(repo_root: Path, debug: bool, binary_name: str) -> Path:
    build_type = "debug" if debug else "release"
    target_dir = repo_root / "target"

    for candidate in _candidate_artifacts(target_dir, build_type, binary_name):
        if candidate.exists():
            return candidate

    # Fallback: cargo may place binaries under target/<build>/deps with hash suffixes.
    search_root = target_dir / build_type
    if search_root.exists():
        for pattern in (
            f"{binary_name}*",
            f"{binary_name.replace('-', '_')}*",
        ):
            for match in search_root.rglob(pattern):
                if match.is_file() and match.suffix in ("", ".elf", ".exe"):
                    return match

    raise BuildError(
        f"Built artifact not found for '{binary_name}' in target directory: {target_dir}"
    )


def cargo_build_service(ctx: Context, service: ServiceConfig, debug: bool, env: dict[str, str] | None = None) -> Path:
    command = ["cargo", "build"]
    if not debug:
        command.append("--release")
    # Merge provided env with service linker env
    merged_env = service.linker_env()
    if env:
        merged_env.update(env)
    run_command(command, cwd=service.service_dir, env=merged_env)
    binary_name = _cargo_package_name(service.service_dir)
    return _resolve_cargo_artifact(service.repo_root, debug, binary_name)
