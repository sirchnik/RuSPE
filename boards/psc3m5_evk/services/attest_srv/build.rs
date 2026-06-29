// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use board_build_scripts::linker;

fn main() {
    linker::generate_service_layout();
}
