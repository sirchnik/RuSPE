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
use ruspe_musca_b1::uart;

mod io;
mod startup;

#[allow(unexpected_cfgs)]
pub mod global_spm_api {
    spe::define_spm_api!(
        spe::spm::SpmFn<ruspe_musca_b1::MuscaB1SecPlatform<InternalPsaClient, SfnApi>>
    );
}

#[unsafe(no_mangle)]
pub unsafe fn main() {
    let serial = unsafe { static_init!(uart::UartMin, uart::UartMin::new_uart0_sec()) };

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

    unsafe {
        (*addr_of_mut!(io::WRITER)).set_serial(serial);
    }

    let sec_platform = unsafe {
        static_init!(
            ruspe_musca_b1::MuscaB1SecPlatform<global_spm_api::InternalPsaClient, global_spm_api::SfnApi>,
            ruspe_musca_b1::MuscaB1SecPlatform {
                initial_attestation: spe_services::attest::attest_service::AttestService::new(
                    ruspe_musca_b1::services::attest::MuscaB1AttestPlatform
                ),
                crypto: spe_services::crypto::crypto_service::CryptoService::new([
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
            spe::spm::SpmFn<
                ruspe_musca_b1::MuscaB1SecPlatform<
                    global_spm_api::InternalPsaClient,
                    global_spm_api::SfnApi,
                >,
            >,
            spe::spm::SpmFn::new(sec_platform)
        )
    };

    let mut sau = cortex_m::sau::new();
    sau.set_region(
        0,
        cortex_m::sau::SauRegion {
            base_address: 0x0010_2000,
            limit_address: 0x0027_FFFF, // Covers rom and prog
            attribute: cortex_m::sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    sau.set_region(
        1,
        cortex_m::sau::SauRegion {
            base_address: 0x1010_0000,
            limit_address: 0x1010_1FFF,
            attribute: cortex_m::sau::SauRegionAttribute::NonSecureCallable,
        },
    )
    .unwrap();
    sau.set_region(
        2,
        cortex_m::sau::SauRegion {
            base_address: 0x2003_0000,
            limit_address: 0x2007_FFFF,
            attribute: cortex_m::sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    sau.set_region(
        3,
        cortex_m::sau::SauRegion {
            base_address: 0x4000_0000,
            limit_address: 0x4FFF_FFFF,
            attribute: cortex_m::sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    sau.set_region(
        4,
        cortex_m::sau::SauRegion {
            base_address: 0x4010_5000,
            limit_address: 0x4010_5FFF,
            attribute: cortex_m::sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();
    sau.enable();

    let _ = global_spm_api::SPM.try_set(spm);

    // Allows SAU to define the code region as a NSC
    ruspe_musca_b1::spcb::enable_idau_nsc_code();

    // Allow non-secure access to UART1
    ruspe_musca_b1::spcb::enable_uart1_ns();

    // QSPI MPC
    let mut eflash_mpc = ruspe_musca_b1::mpc::Mpc::new(0x52000000, 0x00000000);
    eflash_mpc.set_non_secure(0x00102000, 0x003F7FFF);

    // External SRAM MPC (QEMU musca-b1 mpc2)
    let mut ext_sram_mpc = ruspe_musca_b1::mpc::Mpc::new(0x52100000, 0x20000000);
    ext_sram_mpc.set_non_secure(0x20030000, 0x2007FFFF);

    // Internal SRAM Bank 1 MPC (0x20020000 - 0x2003FFFF)
    let mut sram1_mpc = ruspe_musca_b1::mpc::Mpc::new(0x50084000, 0x20020000);
    sram1_mpc.set_non_secure(0x20030000, 0x2003FFFF);

    // Internal SRAM Bank 2 MPC (0x20040000 - 0x2005FFFF)
    let mut sram2_mpc = ruspe_musca_b1::mpc::Mpc::new(0x50085000, 0x20040000);
    sram2_mpc.set_non_secure(0x20040000, 0x2005FFFF);

    // Internal SRAM Bank 3 MPC (0x20060000 - 0x2007FFFF)
    let mut sram3_mpc = ruspe_musca_b1::mpc::Mpc::new(0x50086000, 0x20060000);
    sram3_mpc.set_non_secure(0x20060000, 0x2007FFFF);

    io::debugln(format_args!("Init SPE done, jumping to non-secure"));

    const NONSECURE_FLASH_START: u32 = 0x0010_2000;

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
