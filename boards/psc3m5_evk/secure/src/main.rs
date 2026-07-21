// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Secure startup and services

#![no_std]
#![no_main]
#![feature(cmse_nonsecure_entry)]
#![feature(abi_cmse_nonsecure_call)]

use core::ptr::addr_of_mut;

use helpers::static_init;
use ruspe_psc3::services::attest::Psc3AttestPlatform;
use ruspe_psc3::{Psc3SecPlatform, configure_security};
use spe::spm;
use spe_services::attest::attest_service;
use spe_services::crypto::crypto_service;
use tock_psc3::{chip, chip_init, icache, peri_clk, scb};

const NONSECURE_FLASH_START: u32 = 0x2202_0000;
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

#[expect(unexpected_cfgs)]
pub mod global_spm_api {
    spe::define_spm_api!(
        spe::spm::spm_fn::SpmFn<crate::Psc3SecPlatform<InternalPsaClient, SfnApi>>
    );
}

#[unsafe(no_mangle)]
pub unsafe fn main() {
    let nonsecure_reset = unsafe { start() };
    nonsecure_reset();
}

/// Separated initialization function to ensure its stack frame is popped
/// before jumping to the non-secure entry point in `main`.
/// Returns the non-secure reset handler address.
#[inline(never)]
unsafe fn start() -> extern "cmse-nonsecure-call" fn() {
    icache::sys_init_enable_cache();
    chip_init::preinit_peripherals();
    chip_init::init_system();
    peri_clk::enable_scb0();

    chip::configure_gpio_secure_states();
    chip::init_scb0_uart_pins();

    let scb0 = unsafe { static_init!(scb::Scb, scb::Scb::new_scb0()) };

    scb0.set_standard_uart_mode();
    scb0.enable_scb();

    unsafe {
        (*addr_of_mut!(io::WRITER)).set_serial(scb0);

        cortex_m::nvic::set_interrupt_non_secure(0, 140);
        cortex_m::nvic::enable_all();
    }

    // useless. strangely only setting vector table in scb from ns works
    // mxcm33::set_ns_vector_table_base(security::NONSECURE_START_FLASH as u32);

    // set msplim. There was one incident where then non-secure handled stack
    // overflow.
    unsafe {
        let stack_base = core::ptr::addr_of!(_sstack) as *mut u32;
        cortex_m::register::set_msplim(stack_base as u32);
    }

    unsafe {
        spe::startup::configure_aircr();
    }

    configure_security(
        NONSECURE_FLASH_START,
        NONSECURE_FLASH_LIMIT,
        NONSECURE_RAM_START,
        NONSECURE_RAM_LIMIT,
    );

    let sec_platform = unsafe {
        static_init!(
            Psc3SecPlatform<global_spm_api::InternalPsaClient, global_spm_api::SfnApi>,
            Psc3SecPlatform {
                initial_attestation: attest_service::AttestService::new(Psc3AttestPlatform::new(Some(0x3200FF00))),
                crypto: crypto_service::CryptoService::new([
                    0xc3, 0xfe, 0xe8, 0x4c, 0x73, 0x49, 0xd8, 0xe8, 0x44, 0x3d, 0xe4, 0xae, 0x65,
                    0xf7, 0xea, 0x3b, 0xb8, 0x09, 0x3b, 0xe9, 0xb1, 0x5b, 0xc4, 0xbd, 0x4a, 0x54,
                    0x95, 0x3c, 0xd3, 0x31, 0xce, 0x1b
                ]),
                api: global_spm_api::SfnApi,
            }
        )
    };

    let spm = unsafe {
        static_init!(
            spm::spm_fn::SpmFn<
                Psc3SecPlatform<global_spm_api::InternalPsaClient, global_spm_api::SfnApi>,
            >,
            spm::spm_fn::SpmFn::new(sec_platform)
        )
    };

    let _ = global_spm_api::SPM.try_set(spm);

    io::debugln(format_args!("Init SPE done, jumping to non-secure"));

    unsafe { spe::startup::jump_to_nonsecure(NONSECURE_FLASH_START) }
}
