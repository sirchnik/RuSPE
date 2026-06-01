// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Secure startup and services

#![no_std]
#![no_main]
#![feature(abi_cmse_nonsecure_call)]

use core::ptr::addr_of_mut;

use helpers::static_init;
use spe::{
    psa::psa_api,
    spm::{self},
};
use spe_services::{attest::attest_service, crypto::crypto_service};
use tock_psc3::{chip, chip_init, gpio, icache, peri_clk, scb};

use ruspe_psc3::{Psc3SecPlatform, configure_security, services::attest::Psc3AttestPlatform};

const NONSECURE_FLASH_START: u32 = 0x2201_8000;
const NONSECURE_FLASH_LIMIT: u32 = 0x2203_FFFF;
const NONSECURE_RAM_START: u32 = 0x2400_4000;
const NONSECURE_RAM_LIMIT: u32 = 0x2400_EFFF;

unsafe extern "Rust" {
    static __veneer_base: ();
    static __veneer_limit: ();
}

// These symbols are defined in the linker script.
unsafe extern "C" {
    /// Beginning of the stack region.
    static _sstack: u8;
}

mod io;
mod startup;

#[unsafe(no_mangle)]
pub unsafe fn main() {
    icache::sys_init_enable_cache();
    chip_init::preinit_peripherals();
    chip_init::init_system();
    peri_clk::enable_scb0();

    chip::init_gpio_pins();

    let scb0 = unsafe { static_init!(scb::Scb, scb::Scb::new_scb0()) };

    scb0.set_standard_uart_mode();
    scb0.enable_scb();

    unsafe {
        (*addr_of_mut!(io::WRITER)).set_serial(scb0);

        cortexm33::nvic::set_interrupt_non_secure(0, 140);
        cortexm33::nvic::enable_all();
    }

    // useless. strangely only setting vector table in scb from ns works
    // mxcm33::set_ns_vector_table_base(security::NONSECURE_START_FLASH as u32);

    // set msplim. There was one incident where then non-secure handled stack overflow.
    cortexm33::support::set_msplim(core::ptr::addr_of!(_sstack) as u32);

    unsafe {
        let aircr = 0xe000ed0c as *mut u32;
        let mut value = aircr.read_volatile();
        value &= 0x0 << 16; // Clear VECTKEY
        aircr.write_volatile(value);
        value |= 0x5fa << 16; // VECTKEY
        value |= 1 << 4; // SYSRESETREQS: allow reset request only from secure
        value |= 1 << 13; // BFHFNMINS: allow hardfault, busfault, nmi handled in non-secure
        aircr.write_volatile(value);
    }

    let gpio = gpio::PsocPins::new(true);

    const GPIO_CONFIG: gpio::PreConfig = gpio::PreConfig {
        out_val: 1,
        drive_mode: gpio::DriveMode::PullUp,
        hsiom: gpio::HsiomFunction::GPIOControlsOut,
        int_edge: false,
        int_mask: 0,
        vtrip: 0,
        fast_slew_rate: true,
        drive_sel: gpio::DriveSelect::Half,
        vreg_en: false,
        ibuf_mode: 0,
        vtrip_sel: 0,
        vref_sel: 0,
        voh_sel: 0,
        non_sec: true,
    };

    gpio.get_pin(gpio::PsocPin::P8_5).preconfigure(&GPIO_CONFIG);
    let led_pin = gpio.get_pin(gpio::PsocPin::P8_4);
    led_pin.preconfigure(&GPIO_CONFIG);

    configure_security(
        NONSECURE_FLASH_START,
        NONSECURE_FLASH_LIMIT,
        NONSECURE_RAM_START,
        NONSECURE_RAM_LIMIT,
    );

    let sec_platform = unsafe {
        static_init!(
            Psc3SecPlatform,
            Psc3SecPlatform {
                initial_attestation: attest_service::AttestService::new(Psc3AttestPlatform),
                crypto: crypto_service::CryptoService::new([
                    0xc3, 0xfe, 0xe8, 0x4c, 0x73, 0x49, 0xd8, 0xe8, 0x44, 0x3d, 0xe4, 0xae, 0x65,
                    0xf7, 0xea, 0x3b, 0xb8, 0x09, 0x3b, 0xe9, 0xb1, 0x5b, 0xc4, 0xbd, 0x4a, 0x54,
                    0x95, 0x3c, 0xd3, 0x31, 0xce, 0x1b
                ]),
            }
        )
    };

    let spm = unsafe { static_init!(spm::SpmFn<Psc3SecPlatform>, spm::SpmFn::new(sec_platform)) };

    psa_api::set_spm(spm);

    io::debugln(format_args!("Init SPE done, jumping to non-secure"));

    #[cfg(all(target_arch = "arm", target_os = "none"))]
    unsafe {
        let nonsecure_start_flash = NONSECURE_FLASH_START as *const [u32; 2];
        let [nonsecure_sp, nonsecure_reset] = nonsecure_start_flash.read_volatile();

        // Set non-secure main stack pointer
        core::arch::asm!(
            "msr msp_ns, {nonsecure_sp}",
            nonsecure_sp = in(reg) nonsecure_sp,
            options(nomem, nostack, preserves_flags),
        );

        let nonsecure_reset = core::mem::transmute::<*const u32, extern "cmse-nonsecure-call" fn()>(
            nonsecure_reset as *const u32,
        );

        nonsecure_reset();
    }
}
