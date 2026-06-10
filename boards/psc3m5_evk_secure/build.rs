// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use tock_build_scripts::default as tock_build;

const LINKER_SCRIPT: &str = "layout.ld";

fn main() {
    tock_build::add_board_dir_to_linker_search_path();
    tock_build::set_and_track_linker_script(LINKER_SCRIPT);
}
