// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use board_build_scripts::ipc;
use board_build_scripts::linker;

fn main() {
    ipc::generate_service_config();

    linker::include_spe_layout();
    linker::add_board_dir_to_linker_search_path();
    linker::set_and_track_linker_script("layout.ld");
}
