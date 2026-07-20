// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]
#![no_main]

//! Tock kernel for the PSC3M5-EVK evaluation board.

use core::fmt::Write;
use core::ptr::addr_of_mut;

use psc3::chip::Psc3DefaultPeripherals;
use psc3::chip_init;
use shared_test_nspe::{initialize_ram_jump_to_test_main, unhandled_interrupt};

unsafe extern "C" {
    fn _estack();
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".vectors")
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static BASE_VECTORS: [unsafe extern "C" fn(); 16] = [
    _estack,
    initialize_ram_jump_to_test_main,
    unhandled_interrupt, // NMI
    unhandled_interrupt, // Hard Fault
    unhandled_interrupt, // MemManage
    unhandled_interrupt, // BusFault
    unhandled_interrupt, // UsageFault
    unhandled_interrupt, // SecureFault
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt, // SVC
    unhandled_interrupt, // DebugMon
    unhandled_interrupt,
    unhandled_interrupt, // PendSV
    unhandled_interrupt, // SysTick
];

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".irqs")
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static IRQS: [unsafe extern "C" fn(); 140] = [unhandled_interrupt; 140];

use helpers::static_init;

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
    // set vector-table when coming from secure world
    unsafe { shared_test_nspe::set_vector_table_offset(BASE_VECTORS.as_ptr().cast::<()>()) };

    unsafe { cortex_m::register::set_msplim(core::ptr::addr_of!(_sstack) as u32) };

    // !Only after chip_init::preinit_peripherals() was called peripheral view for
    // debugging works!
    chip_init::preinit_peripherals();

    let peripherals =
        unsafe { static_init!(Psc3DefaultPeripherals, Psc3DefaultPeripherals::new(psc3::gpio::SecurityState::NonSecure)) };

    peripherals.init();

    // Set the UART used for panic
    unsafe { (*addr_of_mut!(io::WRITER)).set_scb(&peripherals.scb3) };

    let writer = unsafe { &mut *addr_of_mut!(io::WRITER) };

    writer.write_fmt(format_args!("NSPE init done")).unwrap();

    shared_test_nspe::run_test(writer);

    loop {}
}
