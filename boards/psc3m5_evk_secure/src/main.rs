// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

//! Secure startup and services

#![no_std]
#![no_main]
#![feature(abi_cmse_nonsecure_call, cmse_nonsecure_entry)]

use core::ptr::addr_of_mut;

use psc3::{chip_init, gpio, icache, peri_clk};
use spe::{
    attest::attest_service::{self},
    crypto::crypto_service,
    psa::psa_api,
    spm::spm::{self},
    static_init,
};

use crate::platform::{Psc3AttestPlatform, Psc3SecPlatform};

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
mod platform;
mod security;
mod startup;

#[unsafe(no_mangle)]
pub unsafe fn main() {
    icache::sys_init_enable_cache();
    chip_init::preinit_peripherals();
    chip_init::init_system();
    peri_clk::enable_scb0();

    psc3::chip::init_gpio_pins();

    let scb0 = unsafe { static_init!(psc3::scb::Scb, psc3::scb::Scb::new_scb0()) };

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

    security::configure_security();

    let sec_platform = unsafe {
        static_init!(
            Psc3SecPlatform,
            Psc3SecPlatform {
                initial_attestation: attest_service::AttestService::new(Psc3AttestPlatform),
                crypto: crypto_service::CryptoService::new([
                    0x3d, 0x42, 0x9a, 0x83, 0xef, 0xe3, 0x87, 0x10, 0xab, 0x9a, 0xb4, 0xc0, 0x2c,
                    0xcb, 0xbe, 0x0b, 0x87, 0xab, 0x69, 0x36, 0xdd, 0xf4, 0x14, 0x57, 0xea, 0x30,
                    0xf9, 0x6c, 0xa6, 0xf2, 0xcd, 0xee,
                ]),
            }
        )
    };

    let spm = unsafe { static_init!(spm::Spm<Psc3SecPlatform>, spm::Spm::new(sec_platform)) };

    psa_api::set_spm(spm);

    io::debugln(format_args!("Init SPE done, jumping to non-secure"));

    #[cfg(all(target_arch = "arm", target_os = "none"))]
    unsafe {
        let [nonsecure_sp, nonsecure_reset] = security::NONSECURE_START_FLASH.read_volatile();

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
