# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from pathlib import Path

# Add repo root to sys.path to allow running from current directory or anywhere
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dataclasses import dataclass

from tools.build.invoke_support import BuildError

@dataclass(frozen=True)
class ServiceSpec:
    name: str
    package_name: str
    mode: str
    service_dir: Path
    generated_import: str
    generated_service_type: str
    generated_service_ctor: str


def _render_main_rs(spec: ServiceSpec) -> str:
    if (
        not spec.generated_import
        or not spec.generated_service_type
        or not spec.generated_service_ctor
    ):
        raise BuildError(
            f"Service '{spec.name}' is missing required generation fields."
        )

    return f"""#![no_std]
#![no_main]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

{spec.generated_import}
use psa_interface::status::into_psa_status;
use spe::{{service::Service, spm::spm_ipc::ServiceVectors, spm_api::PsaMsg}};

static SERVICE: {spec.generated_service_type} = {spec.generated_service_ctor};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn call(msg: *const PsaMsg) -> ! {{
    let msg = unsafe {{ &*msg }};
    let status = into_psa_status(SERVICE.call(*msg, &spe::spm_api::SvcApi));
    // stack gets reset by SPM on every call, so we can just exit the process here
    unsafe {{
        core::arch::asm!(
            "svc {{SVC_PROCESS_EXIT}}",
            SVC_PROCESS_EXIT = const spe::spm_api::SVC_PROCESS_EXIT,
            in("r0") status,
            options(noreturn)
        )
    }}
}}

// External linker symbols for memory initialization
unsafe extern "C" {{
    static _rom_start: u8;
    static _rom_limit: u8;
    static _ram_start: u8;
    static _ram_limit: u8;
    static _stack_limit: u8;
    static _stack_top: u8;
}}

#[unsafe(link_section = ".vectors")]
#[used]
pub static BASE_VECTORS: ServiceVectors = ServiceVectors {{
    version: <{spec.generated_service_type}>::VERSION,
    init_entry: spe::service::init,
    call_entry: call,
    rom_start: core::ptr::addr_of!(_rom_start),
    rom_limit: core::ptr::addr_of!(_rom_limit),
    ram_start: core::ptr::addr_of!(_ram_start),
    ram_limit: core::ptr::addr_of!(_ram_limit),
    stack_limit: core::ptr::addr_of!(_stack_limit),
    stack_top: core::ptr::addr_of!(_stack_top),
}};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {{
    loop {{}}
}}
"""


def _render_cargo_toml(spec: ServiceSpec) -> str:
    return f"""# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

[package]
name = "{spec.package_name}"
version.workspace = true
authors.workspace = true
edition.workspace = true
build = "./build.rs"

[dependencies]
ruspe_psc3 = {{ package = "psc3", path = "../../../../chips/psc3" }}
spe = {{ path = "../../../../spe/spe", features = ["spm-ipc"] }}
spe_services = {{ path = "../../../../spe/spe_services" }}
psa_interface = {{ path = "../../../../spe/psa_interface" }}
helpers = {{ path = "../../../../libraries/helpers" }}

[build-dependencies]
board_build_scripts = {{ path = "../../../shared/build_scripts" }}

[lints]
workspace = true
"""


def _render_build_rs() -> str:
    return """// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use board_build_scripts::linker;

fn main() {
    linker::generate_service_layout();
}
"""


def _render_cargo_config_toml() -> str:
    return """# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

include = ["../../../../shared/cargo/embedded_flags.toml"]

[build]
target = "thumbv8m.main-none-eabi"
"""


def generate_service_crate(
    repo_root: Path, spec: ServiceSpec, force: bool = False
) -> Path:
    if spec.mode != "generated":
        raise BuildError(
            f"Service '{spec.name}' is configured as '{spec.mode}' and cannot be generated."
        )

    service_dir = spec.service_dir
    if service_dir.exists():
        if not force:
            raise BuildError(
                f"Service directory already exists: {service_dir}. Pass force=True to overwrite generated files."
            )
    else:
        service_dir.mkdir(parents=True, exist_ok=True)

    (service_dir / "src").mkdir(parents=True, exist_ok=True)
    (service_dir / ".cargo").mkdir(parents=True, exist_ok=True)

    (service_dir / "Cargo.toml").write_text(_render_cargo_toml(spec), encoding="utf-8")
    (service_dir / "build.rs").write_text(_render_build_rs(), encoding="utf-8")
    (service_dir / ".cargo" / "config.toml").write_text(
        _render_cargo_config_toml(),
        encoding="utf-8",
    )
    (service_dir / "src" / "main.rs").write_text(
        _render_main_rs(spec), encoding="utf-8"
    )

    return service_dir



