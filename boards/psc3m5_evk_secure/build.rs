// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

use tock_build_scripts::default as tock_build;

const LINKER_SCRIPT: &str = "layout.ld";

fn main() {
    tock_build::add_board_dir_to_linker_search_path();
    tock_build::set_and_track_linker_script(LINKER_SCRIPT);
}
