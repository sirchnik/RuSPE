// SPDX-FileCopyrightText: Infineon Technologies AG
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
    // Set the generated linker script path
    tock_build::set_and_track_linker_script(layout_path.to_string_lossy().to_string());
}
