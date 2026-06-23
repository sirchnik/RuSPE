// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Secure startup and services

#![no_std]
#![no_main]
#![feature(abi_cmse_nonsecure_call)]

use core::ptr::addr_of_mut;

use helpers::static_init;
use tock_musca_b1::uart;

mod io;
mod startup;

#[unsafe(no_mangle)]
pub unsafe fn main() {
    unsafe {
        tock_musca_b1::init();
    }

    let uart0_sec = unsafe { static_init!(uart::Uart, uart::Uart::new_uart0_sec()) };
    
    let uart_params = kernel::hil::uart::Parameters {
        baud_rate: 115200,
        width: kernel::hil::uart::Width::Eight,
        stop_bits: kernel::hil::uart::StopBits::One,
        parity: kernel::hil::uart::Parity::None,
        hw_flow_control: false,
    };
    let _ = uart0_sec.debug_configure(uart_params);

    unsafe {
        (*addr_of_mut!(io::WRITER)).set_serial(uart0_sec);
        
        cortexm33::nvic::enable_all();
    }

    let sec_platform = unsafe {
        static_init!(
            ruspe_musca_b1::MuscaB1SecPlatform,
            ruspe_musca_b1::MuscaB1SecPlatform {
                initial_attestation: spe_services::attest::attest_service::AttestService::new(
                    ruspe_musca_b1::services::attest::MuscaB1AttestPlatform
                ),
                crypto: spe_services::crypto::crypto_service::CryptoService::new([
                    0xc3, 0xfe, 0xe8, 0x4c, 0x73, 0x49, 0xd8, 0xe8, 0x44, 0x3d, 0xe4, 0xae, 0x65,
                    0xf7, 0xea, 0x3b, 0xb8, 0x09, 0x3b, 0xe9, 0xb1, 0x5b, 0xc4, 0xbd, 0x4a, 0x54,
                    0x95, 0x3c, 0xd3, 0x31, 0xce, 0x1b
                ]),
            }
        )
    };

    let spm = unsafe { static_init!(spe::spm::SpmFn<ruspe_musca_b1::MuscaB1SecPlatform>, spe::spm::SpmFn::new(sec_platform)) };

    spe::psa::psa_api::set_spm(spm);

    io::debugln(format_args!("Init SPE done, jumping to non-secure"));

    loop {}
}
