# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import shutil
from pathlib import Path

from tools.build.invoke_support import BuildError
from tools.build.service_catalog import ServiceSpec

def _render_main_rs(spec: ServiceSpec) -> str:
    if not spec.generated_import or not spec.generated_service_type or not spec.generated_service_ctor:
        raise BuildError(
            f"Service '{spec.name}' is missing required generation fields."
        )

    return f"""#![no_std]
#![no_main]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

{spec.generated_import}
use spe::{{into_psa_status, psa::psa_call::PsaMsg, service::Service, spm::FlashProcessVectors}};

static SERVICE: {spec.generated_service_type} = {spec.generated_service_ctor};

#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn call(msg: *const PsaMsg) -> psa_interface::types::PsaStatus {{
    let msg = unsafe {{ &*msg }};
    into_psa_status(SERVICE.call(*msg))
}}

// External linker symbols for memory initialization
unsafe extern \"C\" {{
    static _rom_start: *const u32;
    static _rom_limit: *const u32;
    static _ram_start: *const u32;
    static _ram_limit: *const u32;
    static _szero: *const u32;
    static _ezero: *const u32;
    static _sdata: *const u32;
    static _edata: *const u32;
    static _etext: *const u32;
    static _stack_limit: *const u32;
    static _stack_top: *const u32;
}}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn init() {{
    use core::arch::naked_asm;
    naked_asm!(
        \"\n        // Initialize BSS section (zero out)\n        ldr r0, ={{szero}}        // r0 = start of BSS\n        ldr r1, ={{ezero}}        // r1 = end of BSS\n        movs r2, #0             // r2 = 0\n\n    bss_loop:\n        cmp r0, r1              // compare pointers\n        beq bss_done            // if equal, done\n        stm r0!, {{{{r2}}}}         // *(r0++) = r2 (zero word)\n        b bss_loop\n\n    bss_done:\n\n        // Initialize DATA section (copy from ROM to RAM)\n        ldr r0, ={{sdata}}        // r0 = start of data in RAM\n        ldr r1, ={{edata}}        // r1 = end of data in RAM\n        ldr r2, ={{etext}}        // r2 = start of data in ROM\n\n    data_loop:\n        cmp r0, r1              // compare pointers\n        beq data_done           // if equal, done\n        ldm r2!, {{{{r3}}}}         // r3 = *(r2++), load from ROM\n        stm r0!, {{{{r3}}}}         // *(r0++) = r3, store to RAM\n        b data_loop\n\n    data_done:\n\n        // Initialize stack pointer\n        ldr sp, ={{stack_top}}\n\n        bx lr\n        \",
        szero = sym _szero,
        ezero = sym _ezero,
        sdata = sym _sdata,
        edata = sym _edata,
        etext = sym _etext,
        stack_top = sym _stack_top,
    );
}}

/// Minimal thunk placed in service flash. When the service function returns,
/// it branches here via LR. The `svc #0` traps back to the SPM's SVC handler
/// which re-elevates to privileged mode and returns to the original caller.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn svc_return() {{
    use core::arch::naked_asm;
    naked_asm!(\"svc #0\");
}}

#[cfg_attr(
    all(target_arch = \"arm\", target_os = \"none\"),
    unsafe(link_section = \".vectors\")
)]
#[cfg_attr(all(target_arch = \"arm\", target_os = \"none\"), used)]
pub static BASE_VECTORS: FlashProcessVectors = FlashProcessVectors {{
    init,
    call,
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
ruspe_psc3 = {{ package = \"psc3\", path = \"../../../chips/psc3\" }}
spe = {{ path = \"../../../spe/spe\" }}
spe_services = {{ path = \"../../../spe/spe_services\" }}
psa_interface = {{ path = \"../../../spe/psa_interface\" }}
helpers = {{ path = \"../../../libraries/helpers\" }}

[build-dependencies]
tock_build_scripts = {{ path = \"../../../tock/boards/build_scripts\" }}

[lints]
workspace = true
"""


def _render_build_rs() -> str:
    return """// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use std::env;
use std::fs;
use std::path::Path;
use tock_build_scripts::default as tock_build;

fn main() {
    let flash_origin = env::var("SERVICE_FLASH_ORIGIN")
        .unwrap_or_else(|_| "0x32010000".to_string())
        .replace("_", "");
    let flash_length = env::var("SERVICE_FLASH_LENGTH")
        .unwrap_or_else(|_| "0x3F00".to_string())
        .replace("_", "");
    let ram_origin = env::var("SERVICE_RAM_ORIGIN")
        .unwrap_or_else(|_| "0x34002F00".to_string())
        .replace("_", "");
    let ram_length = env::var("SERVICE_RAM_LENGTH")
        .unwrap_or_else(|_| "0x1100".to_string())
        .replace("_", "");

    // Track env variables so cargo rebuilds if they change
    println!("cargo:rerun-if-env-changed=SERVICE_FLASH_ORIGIN");
    println!("cargo:rerun-if-env-changed=SERVICE_FLASH_LENGTH");
    println!("cargo:rerun-if-env-changed=SERVICE_RAM_ORIGIN");
    println!("cargo:rerun-if-env-changed=SERVICE_RAM_LENGTH");

    // Generate layout.ld in OUT_DIR with configured memory regions
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR env var not set");
    let layout_path = Path::new(&out_dir).join("layout.ld");

    let layout_content = format!(
        r#"
/* Generated linker script with configured memory layout */
MEMORY
{{
    ROM (rx)  : ORIGIN = {}, LENGTH = {}
    RAM (rwx) : ORIGIN = {}, LENGTH = {}
}}

INCLUDE ../../../shared/linker/service_layout.ld
"#,
        flash_origin, flash_length, ram_origin, ram_length
    );

    fs::write(&layout_path, layout_content).expect("Failed to write generated layout.ld");

    tock_build::add_board_dir_to_linker_search_path();
    tock_build::set_and_track_linker_script(layout_path.to_string_lossy().to_string());
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


def generate_service_crate(repo_root: Path, spec: ServiceSpec, force: bool = False) -> Path:
    if spec.mode != "generated":
        raise BuildError(
            f"Service '{spec.name}' is configured as '{spec.mode}' and cannot be generated."
        )

    service_dir = spec.service_dir
    if service_dir.exists():
        if not force:
            raise BuildError(
                f"Service directory already exists: {service_dir}. Pass force=True to replace it."
            )
        shutil.rmtree(service_dir)

    (service_dir / "src").mkdir(parents=True, exist_ok=True)
    (service_dir / ".cargo").mkdir(parents=True, exist_ok=True)

    (service_dir / "Cargo.toml").write_text(_render_cargo_toml(spec), encoding="utf-8")
    (service_dir / "build.rs").write_text(_render_build_rs(), encoding="utf-8")
    (service_dir / ".cargo" / "config.toml").write_text(
        _render_cargo_config_toml(),
        encoding="utf-8",
    )
    (service_dir / "src" / "main.rs").write_text(_render_main_rs(spec), encoding="utf-8")

    return service_dir
