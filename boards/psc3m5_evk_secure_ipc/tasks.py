# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build.invoke_support import BuildError, build_task
from tools.build.board import (
    BoardConfig,
    Manufacturer,
    build_non_secure,
    cargo_build,
    elf_to_hex,
    merge_hex_images,
    debug_with_gdb,
    program_hex,
)

from boards.services.attest_srv.tasks import build as _attest_build_task
from boards.services.crypto_srv.tasks import build as _crypto_build_task

BOARD = BoardConfig(
    board_dir=Path(__file__).resolve().parent,
    repo_root=REPO_ROOT,
    manufacturer=Manufacturer.INFINEON,
    chip="PSC3M5FDS2AFQ1",
)

DEBUG_HELP = "Build the debug profile instead of release."

BuildEnv = dict[str, str]


class ServiceBuilder(Protocol):
    def __call__(self, ctx: Context, *, debug: bool = False) -> tuple[Path, BuildEnv]: ...


build_attest = cast(ServiceBuilder, _attest_build_task.body)
del _attest_build_task
build_crypto = cast(ServiceBuilder, _crypto_build_task.body)
del _crypto_build_task


@dataclass(frozen=True)
class BuiltService:
    elf_path: Path
    hex_path: Path
    env: BuildEnv


SERVICES: tuple[ServiceBuilder, ...] = (
    build_attest,
    build_crypto,
)


def build_service_hex(ctx: Context, service_build: ServiceBuilder, debug: bool) -> BuiltService:
    service_elf, env = service_build(ctx, debug=debug)
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
    """Merge service environments using indexed keys for multiple services.
    
    Transforms single-service env keys to indexed format:
    - SERVICE_FLASH_ORIGIN -> SERVICE_FLASH_ORIGIN_0, SERVICE_FLASH_ORIGIN_1, ...
    - SERVICE_HANDLE_VARIANT -> SERVICE_HANDLE_VARIANT_0, SERVICE_HANDLE_VARIANT_1, ...
    """
    merged: BuildEnv = {"SERVICE_COUNT": str(len(services))}
    
    for idx, service in enumerate(services):
        for key, value in service.env.items():
            # Index service-specific keys
            if key.startswith("SERVICE_"):
                indexed_key = f"{key}_{idx}"
            else:
                indexed_key = key
            
            if indexed_key in merged:
                # Check for conflicts in indexed keys; non-indexed keys can be shared
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


@build_task(
    default=True,
    help={"debug": DEBUG_HELP},
)
def build(ctx: Context, debug: bool = False) -> tuple[Path, list[BuiltService]]:
    """Build secure IPC kernel and selected services."""
    debug = bool(debug)

    services = [build_service_hex(ctx, service, debug) for service in SERVICES]
    service_env = merge_service_envs(services)

    kernel_elf = cargo_build(ctx, BOARD, debug, env=service_env)

    return kernel_elf, services
