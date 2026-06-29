// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;

const LINKER_SCRIPT: &str = "layout.ld";

/// Setup the Tock board to build with a board-provided linker script called
/// `layout.ld`.
///
/// The board linker script (i.e., `layout.ld`) should end with the command:
///
/// INCLUDE shared_layout.ld
///
/// This function will ensure that the linker's search path is configured to
/// find `shared_layout.ld`.
pub fn default_linker_script() {
    if !Path::new(LINKER_SCRIPT).exists() {
        panic!("Boards must provide a `layout.ld` link script file");
    }

    include_spe_layout();
    include_test_nspe_layout();
    include_service_layout();

    add_board_dir_to_linker_search_path();

    set_and_track_linker_script(LINKER_SCRIPT);
}

/// Include the folder where the board's Cargo.toml is in the linker file
/// search path.
pub fn add_board_dir_to_linker_search_path() {
    println!(
        "cargo:rustc-link-arg=-L{}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
}

pub fn include_spe_layout() {
    println!("cargo:rustc-link-arg=-L{}", std::env!("CARGO_MANIFEST_DIR"));
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(std::env!("CARGO_MANIFEST_DIR"))
            .join("spe_layout.ld")
            .to_string_lossy()
    );
}

pub fn include_test_nspe_layout() {
    println!("cargo:rustc-link-arg=-L{}", std::env!("CARGO_MANIFEST_DIR"));
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(std::env!("CARGO_MANIFEST_DIR"))
            .join("test_nspe_layout.ld")
            .to_string_lossy()
    );
}

pub fn include_service_layout() {
    println!("cargo:rustc-link-arg=-L{}", std::env!("CARGO_MANIFEST_DIR"));
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(std::env!("CARGO_MANIFEST_DIR"))
            .join("service_layout.ld")
            .to_string_lossy()
    );
}

/// Pass the given linker script to cargo, and track it and all of its `INCLUDE`s
pub fn set_and_track_linker_script<P: AsRef<Path> + ToString>(path: P) {
    // Use the passed linker script
    println!("cargo:rustc-link-arg=-T{}", path.to_string());
    track_linker_script(path);
}

/// Track the given linker script and all of its `INCLUDE`s so that the build
/// is rerun when any of them change.
pub fn track_linker_script<P: AsRef<Path>>(path: P) {
    let path = path.as_ref();

    if path.to_str() == Some("spe_layout.ld")
        || path.to_str() == Some("test_nspe_layout.ld")
        || path.to_str() == Some("service_layout.ld")
    {
        return;
    }

    assert!(path.is_file(), "expected path {path:?} to be a file");

    println!("cargo:rerun-if-changed={}", path.display());

    // Find all the `INCLUDE <relative path>` lines in the linker script.
    let link_script = fs::read_to_string(path).expect("failed to read {path:?}");
    let includes = link_script
        .lines()
        .filter_map(|line| line.strip_prefix("INCLUDE").map(str::trim));

    // Recursively track included linker scripts.
    for include in includes {
        track_linker_script(include);
    }
}

pub fn generate_service_layout() {
    let flash_origin = std::env::var("SERVICE_FLASH_ORIGIN")
        .unwrap_or_else(|_| "0x32010000".to_string())
        .replace("_", "");
    let flash_length = std::env::var("SERVICE_FLASH_LENGTH")
        .unwrap_or_else(|_| "0x3F00".to_string())
        .replace("_", "");
    let ram_origin = std::env::var("SERVICE_RAM_ORIGIN")
        .unwrap_or_else(|_| "0x34002F00".to_string())
        .replace("_", "");
    let ram_length = std::env::var("SERVICE_RAM_LENGTH")
        .unwrap_or_else(|_| "0x1100".to_string())
        .replace("_", "");

    // Track env variables so cargo rebuilds if they change
    println!("cargo:rerun-if-env-changed=SERVICE_FLASH_ORIGIN");
    println!("cargo:rerun-if-env-changed=SERVICE_FLASH_LENGTH");
    println!("cargo:rerun-if-env-changed=SERVICE_RAM_ORIGIN");
    println!("cargo:rerun-if-env-changed=SERVICE_RAM_LENGTH");

    // Generate layout.ld in OUT_DIR with configured memory regions
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR env var not set");
    let layout_path = Path::new(&out_dir).join("layout.ld");

    let layout_content = format!(
        r#"
/* Generated linker script with configured memory layout */
MEMORY
{{
    ROM (rx)  : ORIGIN = {}, LENGTH = {}
    RAM (rwx) : ORIGIN = {}, LENGTH = {}
}}

INCLUDE service_layout.ld
"#,
        flash_origin, flash_length, ram_origin, ram_length
    );

    fs::write(&layout_path, layout_content).expect("Failed to write generated layout.ld");

    include_service_layout();
    add_board_dir_to_linker_search_path();
    set_and_track_linker_script(layout_path.to_string_lossy().to_string());
}
