// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use board_build_scripts::ipc;
use board_build_scripts::linker as tock_build;

fn main() {
    ipc::generate_service_config();

    tock_build::include_spe_layout();
    tock_build::add_board_dir_to_linker_search_path();
    tock_build::set_and_track_linker_script("layout.ld");
}
