// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use board_build_scripts::linker;

const LINKER_SCRIPT_NSEC: &str = "layout.ld";
const SECURE_VENEERS_OBJ: &str = "target/thumbv8m.main-none-eabi/musca_b1_secure-veneers.o";

fn main() {
    linker::include_test_nspe_layout();
    linker::add_board_dir_to_linker_search_path();

    println!("cargo:rustc-link-arg={}", SECURE_VENEERS_OBJ);
    println!("cargo:rerun-if-changed={}", SECURE_VENEERS_OBJ);
    linker::set_and_track_linker_script(LINKER_SCRIPT_NSEC);
}
