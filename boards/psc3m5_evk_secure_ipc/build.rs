// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use std::env;
use std::fs;
use std::path::Path;
use tock_build_scripts::default as tock_build;

fn main() {
    println!("cargo:rerun-if-env-changed=SERVICE_COUNT");

    let service_count = read_service_count();
    let services = read_service_configs(service_count);

    if service_count == 0 {
        panic!("At least one service must be configured (SERVICE_COUNT must be greater than zero)");
    }

    // Track the exact service env variables used by this build.
    for i in 0..service_count {
        println!("cargo:rerun-if-env-changed=SERVICE_FLASH_ORIGIN_{}", i);
        println!("cargo:rerun-if-env-changed=SERVICE_HANDLE_VARIANT_{}", i);
    }

    // Generate service_config.rs with all service configurations
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR env var not set");
    let config_path = Path::new(&out_dir).join("service_config.rs");

    let mut config_content = String::from(
        "// Generated service configuration from build time\n\n"
    );

    config_content.push_str(&format!("pub const SERVICE_COUNT: usize = {};\n\n", service_count));
    config_content.push_str("pub const SERVICE_ADDRS: [u32; SERVICE_COUNT] = [\n");
    for service in &services {
        config_content.push_str(&format!("    {},\n", service.flash_origin));
    }
    config_content.push_str("];\n\n");

    config_content.push_str(
        "pub const SERVICE_HANDLES: [psa_interface::types::ServiceHandle; SERVICE_COUNT] = [\n"
    );
    for service in &services {
        config_content.push_str(&format!("    {},\n", service.handle_variant));
    }
    config_content.push_str("];\n");

    fs::write(&config_path, config_content)
        .expect("Failed to write generated service_config.rs");

    tock_build::add_board_dir_to_linker_search_path();
    tock_build::set_and_track_linker_script("layout.ld");
}

struct ServiceConfig {
    flash_origin: String,
    handle_variant: String,
}

fn read_service_count() -> usize {
    env::var("SERVICE_COUNT")
        .expect("Missing SERVICE_COUNT env var")
        .parse()
        .expect("SERVICE_COUNT must be a valid usize")
}

fn read_service_configs(service_count: usize) -> Vec<ServiceConfig> {
    let mut services = Vec::with_capacity(service_count);

    for i in 0..service_count {
        let origin_key = format!("SERVICE_FLASH_ORIGIN_{}", i);
        let handle_key = format!("SERVICE_HANDLE_VARIANT_{}", i);

        let flash_origin = env::var(&origin_key)
            .unwrap_or_else(|_| panic!("Missing {} for service {}", origin_key, i))
            .replace("_", "");

        let handle_variant = env::var(&handle_key)
            .unwrap_or_else(|_| panic!("Missing {} for service {}", handle_key, i));

        services.push(ServiceConfig {
            flash_origin,
            handle_variant,
        });
    }

    services
}
