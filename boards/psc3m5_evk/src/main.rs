// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#![no_std]
#![no_main]
#![deny(missing_docs)]

//! Tock kernel for the PSC3M5-EVK evaluation board.

use core::ptr::addr_of_mut;

use psc3::chip::{Psc3, Psc3DefaultPeripherals};
use psc3::tcpwm::Tcpwm0;
use psc3::{chip_init, gpio};
#[allow(unused)]
use psc3::{BASE_VECTORS, IRQS};

use kernel::static_init;

use psa_interface::{self, psa_api};

use psa_veneer_client::{self, PsaVeneerClient};

mod io;

// Allocate memory for the stack
kernel::stack_size! {0x1000}

// These symbols are defined in the linker script.
extern "C" {
    /// Beginning of the ROM region containing app images.
    static _sapps: u8;
    /// End of the ROM region containing app images.
    static _eapps: u8;
    /// Beginning of the RAM region for app memory.
    static mut _sappmem: u8;
    /// End of the RAM region for app memory.
    static _eappmem: u8;
    /// Beginning of the stack region.
    static _sstack: u8;
}

/// Main function called after RAM initialized.
#[no_mangle]
pub unsafe fn main() {
    cortexm33::support::dmb();
    // set vector-table when coming from secure world
    cortexm33::scb::set_vector_table_offset(BASE_VECTORS.as_ptr().cast::<()>());

    cortexm33::support::set_msplim(core::ptr::addr_of!(_sstack) as u32);

    /* !Only after chip_init::preinit_peripherals() was called peripheral view for debugging works! */
    chip_init::preinit_peripherals();

    let peripherals = static_init!(Psc3DefaultPeripherals, Psc3DefaultPeripherals::new());

    peripherals.init();

    // Set the UART used for panic
    (*addr_of_mut!(io::WRITER)).set_scb(&peripherals.scb3);

    let challenge = [0u8; 32];
    let mut token_buf = [0u8; 512];

    psa_api::initial_attest_get_token::<PsaVeneerClient>(&challenge, &mut token_buf).unwrap();

    use core::fmt::Write;

    let writer = unsafe { &mut *addr_of_mut!(io::WRITER) };
    let _ = write!(writer, "\r\ntoken_buf: ");

    for b in token_buf {
        let _ = write!(writer, "{:02x}", b);
    }

    let _ = write!(writer, "\r\n");

    loop {}
}
