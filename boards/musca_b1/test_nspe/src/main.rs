// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]
#![no_main]

//! Tock kernel for the PSC3M5-EVK evaluation board.

use core::ptr::addr_of_mut;

use cortexm33::{CortexM33, CortexMVariant, initialize_ram_jump_to_main, unhandled_interrupt};

unsafe extern "C" {
    // _estack is not really a function, but it makes the types work
    // You should never actually invoke it!!
    fn _estack();
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".vectors")
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static BASE_VECTORS: [unsafe extern "C" fn(); 16] = [
    _estack,
    initialize_ram_jump_to_main,
    unhandled_interrupt,           // NMI
    CortexM33::HARD_FAULT_HANDLER, // Hard Fault
    unhandled_interrupt,           // MemManage
    unhandled_interrupt,           // BusFault
    unhandled_interrupt,           // UsageFault
    unhandled_interrupt,           // SecureFault
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    CortexM33::SVC_HANDLER, // SVC
    unhandled_interrupt,    // DebugMon
    unhandled_interrupt,
    unhandled_interrupt,        // PendSV
    CortexM33::SYSTICK_HANDLER, // SysTick
];

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".irqs")
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static IRQS: [unsafe extern "C" fn(); 97] = [CortexM33::GENERIC_ISR; 97];

use helpers::static_init;

use ruspe_musca_b1::uart;

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

    let serial = unsafe { static_init!(uart::UartMin, uart::UartMin::new_uart1_nsec()) };

    // Configure UART (assuming musca_b1 system clock is 50MHz, baud 115200)
    serial.configure(
        uart::Parameters {
            baud_rate: 115200,
            width: uart::Width::Eight,
            parity: uart::Parity::None,
            stop_bits: uart::StopBits::One,
            hw_flow_control: false,
        },
        50_000_000,
    );

    // Set the UART used for panic
    unsafe { (*addr_of_mut!(io::WRITER)).set_uart(serial) };

    io::debugln(format_args!("Init NSPE done"));

    let writer = unsafe { &mut *addr_of_mut!(io::WRITER) };
    shared_test_nspe::run_attestation_test(writer);

    loop {
        core::hint::spin_loop();
    }
}
