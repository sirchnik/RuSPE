// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]
#![no_main]
#![deny(missing_docs)]

//! Tock kernel for the PSC3M5-EVK evaluation board.

use core::ptr::addr_of_mut;

use musca_b1::chip::MuscaB1DefaultPeripherals;
use musca_b1::init;
#[allow(unused)]
use musca_b1::{BASE_VECTORS, IRQS};

use helpers::static_init;

use psa_interface::{self, psa_api};

use psa_veneer_client::{self, PsaVeneerClient};

mod io;

// Allocate memory for the stack
#[unsafe(link_section = ".stack_buffer")]
#[unsafe(no_mangle)]
static mut STACK_MEMORY: [u8; 0x3000] = [0; 0x3000];

// These symbols are defined in the linker script.
unsafe extern "C" {
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
#[unsafe(no_mangle)]
pub unsafe fn main() {
    cortexm33::support::dmb();
    // set vector-table when coming from secure world
    unsafe { cortexm33::scb::set_vector_table_offset(BASE_VECTORS.as_ptr().cast::<()>()) };

    cortexm33::support::set_msplim(core::ptr::addr_of!(_sstack) as u32);

    unsafe { init() };

    let peripherals =
        unsafe { static_init!(MuscaB1DefaultPeripherals, MuscaB1DefaultPeripherals::new()) };

    peripherals.resolve_dependencies();

    // Set the UART used for panic
    unsafe { (*addr_of_mut!(io::WRITER)).set_uart(&peripherals.uart0) };

    #[repr(align(32))]
    struct Aligned32<T>(T);

    let challenge = Aligned32([0u8; 32]);
    let mut token_buf = Aligned32([0u8; 512]);

    psa_api::initial_attest_get_token::<PsaVeneerClient>(&challenge.0, &mut token_buf.0).unwrap();

    use core::fmt::Write;

    let writer = unsafe { &mut *addr_of_mut!(io::WRITER) };
    let _ = write!(writer, "\r\ntoken_buf: ");

    for b in token_buf.0 {
        let _ = write!(writer, "{:02x}", b);
    }

    let _ = write!(writer, "\r\n");

    loop {}
}
