// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

use tock_build_scripts::default as tock_build;

const LINKER_SCRIPT_NSEC: &str = "layout_non_secure.ld";
const LINKER_SCRIPT_SEC: &str = "layout_secure.ld";
const SECURE_VENEERS_OBJ: &str = "target/thumbv8m.main-none-eabi/psc3m5_secure-veneers.o";

fn main() {
    tock_build::rustflags_check();
    tock_build::include_tock_kernel_layout();
    tock_build::add_board_dir_to_linker_search_path();

    let non_secure_tz_enabled = std::env::var_os("CARGO_FEATURE_NON_SECURE_TZ").is_some();

    if non_secure_tz_enabled {
        println!("cargo:rustc-link-arg={}", SECURE_VENEERS_OBJ);
        println!("cargo:rerun-if-changed={}", SECURE_VENEERS_OBJ);
        tock_build::set_and_track_linker_script(LINKER_SCRIPT_NSEC);
    } else {
        tock_build::set_and_track_linker_script(LINKER_SCRIPT_SEC);
    }
}
