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

from tools.build.invoke_support import BuildError
from tools.generate.service_catalog import ServiceSpec


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
pub unsafe extern \"C\" fn call(msg: *const PsaMsg) -> psa_interface::types::PsaStatus {{
    let msg = unsafe {{ &*msg }};
    into_psa_status(SERVICE.call(*msg, &spe::spm_api::SvcApi))
}}

// External linker symbols for memory initialization
unsafe extern \"C\" {{
    static _rom_start: *const u32;
    static _rom_limit: *const u32;
    static _ram_start: *const u32;
    static _ram_limit: *const u32;
    static _stack_limit: *const u32;
    static _stack_top: *const u32;
}}

/// Minimal thunk placed in service flash. When the service function returns,
/// it branches here via LR. The `svc` traps back to the SPM's SVC handler
/// which re-elevates to privileged mode and returns to the original caller.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn svc_return() {{
    use core::arch::naked_asm;
    naked_asm!(
        \"svc {{SVC_PROCESS_EXIT}}\",
        SVC_PROCESS_EXIT = const spe::spm_api::SVC_PROCESS_EXIT,
    );
}}

#[cfg_attr(
    all(target_arch = \"arm\", target_os = \"none\"),
    unsafe(link_section = \".vectors\")
)]
#[cfg_attr(all(target_arch = \"arm\", target_os = \"none\"), used)]
pub static BASE_VECTORS: ServiceVectors = ServiceVectors {{
    init_entry: spe::service::init,
    call_entry: call,
    rom_start: unsafe {{ &_rom_start as *const _ as *const u8 }},
    rom_limit: unsafe {{ &_rom_limit as *const _ as *const u8 }},
    ram_start: unsafe {{ &_ram_start as *const _ as *const u8 }},
    ram_limit: unsafe {{ &_ram_limit as *const _ as *const u8 }},
    svc_return,
    stack_limit: unsafe {{ &_stack_limit as *const _ as *const u8 }},
    stack_top: unsafe {{ &_stack_top as *const _ as *const u8 }},
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
name = \"{spec.package_name}\"
version.workspace = true
authors.workspace = true
edition.workspace = true
build = \"./build.rs\"

[dependencies]
ruspe_psc3 = {{ package = \"psc3\", path = \"../../../../chips/psc3\" }}
spe = {{ path = \"../../../../spe/spe\", features = [\"spm-ipc\"] }}
spe_services = {{ path = \"../../../../spe/spe_services\" }}
psa_interface = {{ path = \"../../../../spe/psa_interface\" }}
helpers = {{ path = \"../../../../libraries/helpers\" }}

[build-dependencies]
board_build_scripts = {{ path = \"../../../shared/build_scripts\" }}

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

include = [\"../../../../shared/cargo/embedded_flags.toml\"]

[build]
target = \"thumbv8m.main-none-eabi\"
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


if __name__ == "__main__":
    import argparse
    from tools.generate.service_catalog import CATALOG

    parser = argparse.ArgumentParser(
        description="Generate a service from the service catalog."
    )
    parser.add_argument(
        "--service",
        required=True,
        choices=list(CATALOG.keys()),
        help="Name of the service to generate",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite generated files if they already exist",
    )

    args = parser.parse_args()
    spec = CATALOG[args.service]

    # repo_root is implicitly spec.service_dir.parents[4] based on structure
    # but generate_service_crate doesn't actually use repo_root, it just takes it.
    repo_root = spec.service_dir.parents[4]

    print(f"Generating service '{spec.name}' at {spec.service_dir}")
    generate_service_crate(repo_root, spec, force=args.force)
    print("Done!")
