# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT


import sys
from pathlib import Path

from invoke.context import Context

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build.service import ServiceConfig, cargo_build_service

SERVICE_DIR = Path(__file__).resolve().parent
BuildEnv = dict[str, str]


SERVICE_CONF = ServiceConfig(
    repo_root=REPO_ROOT,
    service_dir=SERVICE_DIR,
    handle_variant="psa_interface::types::ServiceHandle::AttestationService",
    flash_origin="0x32010000",
    flash_length="0x4800",
    ram_origin="0x34002300",
    ram_length="0x1800",
)


def build(ctx: Context, debug: bool = False) -> tuple[Path, BuildEnv]:
    """Build the attest service and return artifact path with IPC wiring env."""
    service_elf = cargo_build_service(ctx, SERVICE_CONF, debug)

    return service_elf, SERVICE_CONF.build_env()


def stats(ctx: Context, debug: bool = False, crates: bool = False):
    """Build the attest service and print stats (arm-none-eabi-size, stack space, and cargo bloat)."""
    service_elf, env = build(ctx, debug)
    from tools.analyze.stats import print_binary_stats

    print_binary_stats(
        title=f"Service: {SERVICE_CONF.crate_name} ({'debug' if debug else 'release'})",
        elf_path=service_elf,
        package_name=SERVICE_CONF.crate_name,
        repo_root=REPO_ROOT,
        cwd=SERVICE_DIR,
        debug=bool(debug),
        crates=bool(crates),
        env=env,
    )
