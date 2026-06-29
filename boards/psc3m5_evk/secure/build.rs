// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use board_build_scripts::linker;

const LINKER_SCRIPT: &str = "layout.ld";

fn main() {
    linker::include_spe_layout();
    linker::add_board_dir_to_linker_search_path();
    linker::set_and_track_linker_script(LINKER_SCRIPT);
}
