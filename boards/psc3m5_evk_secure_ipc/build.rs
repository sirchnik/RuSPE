// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use std::env;
use std::fs;
use std::path::Path;
use tock_build_scripts::default as tock_build;

fn main() {
    let flash_origin = env::var("SERVICE_FLASH_ORIGIN")
        .unwrap_or_else(|_| "0x3201_0000".to_string())
        .replace("_", "");

    // Track env variable so cargo rebuilds if it changes
    println!("cargo:rerun-if-env-changed=SERVICE_FLASH_ORIGIN");

    // Generate service_config.rs with the service vector base address
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR env var not set");
    let config_path = Path::new(&out_dir).join("service_config.rs");

    let config_content = format!(
        r#"// Generated service configuration with address from build time
pub const ATTEST_SERVICE_ADDR: u32 = {};
"#,
        flash_origin
    );

    fs::write(&config_path, config_content)
        .expect("Failed to write generated service_config.rs");

    tock_build::add_board_dir_to_linker_search_path();
    tock_build::set_and_track_linker_script("layout.ld");
}
