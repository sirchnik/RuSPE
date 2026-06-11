# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

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
    flash_length="0x3800",
    ram_origin="0x34002300",
    ram_length="0x1000",
)


def build(ctx: Context, debug: bool = False) -> tuple[Path, BuildEnv]:
    """Build the attest service and return artifact path with IPC wiring env."""
    service_elf = cargo_build_service(ctx, SERVICE_CONF, debug)

    return service_elf, SERVICE_CONF.build_env()
