// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2024.

const LINKER_SCRIPT: &str = "layout.ld";

fn main() {
    println!("cargo:rustc-link-arg=-L{}", std::env!("CARGO_MANIFEST_DIR"));
    tock_build_scripts::default::set_and_track_linker_script(LINKER_SCRIPT);
}
