// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]

use core::fmt::Write;
use psa_interface::psa_api;
use psa_veneer_client::PsaVeneerClient;

#[repr(align(32))]
struct Aligned32<T>(T);

pub fn run_attestation_test(writer: &mut dyn Write) {
    let challenge = Aligned32([0u8; 32]);
    let mut token_buf = Aligned32([0u8; 512]);

    psa_api::initial_attest_get_token::<PsaVeneerClient>(&challenge.0, &mut token_buf.0).unwrap();

    let _ = write!(writer, "\r\ntoken_buf: ");

    for b in token_buf.0 {
        let _ = write!(writer, "{:02x}", b);
    }

    let _ = write!(writer, "\r\n");
}
