// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! An extremely simple libtock-rs example. Register button events.

#![no_main]
#![no_std]
#![allow(dead_code)]

use core::fmt::Write;

use libtock::console::Console;
use libtock::platform::Syscalls;
use libtock::runtime::{TockSyscalls, set_main, stack_size};

mod spe_driver;
use spe_driver::SpeDriver;

const APP_STACK_SIZE: usize = 0x400;

set_main! {main}
stack_size! {APP_STACK_SIZE}

#[repr(align(32))]
struct Aligned32<T>(T);

#[derive(Debug)]
enum TokenError {
    ConsoleRead,
    SpeDriverNotAvailable,
    TokenRequestFailed,
    WriteError,
}

fn parse_hex(hex_input: &[u8], output: &mut [u8]) -> usize {
    let mut out_idx = 0;
    let mut i = 0;

    while i < hex_input.len() && out_idx < output.len() {
        let byte1 = hex_input[i];
        if byte1 == b' ' || byte1 == b'\n' || byte1 == b'\r' {
            i += 1;
            continue;
        }

        let hex1 = match byte1 {
            b'0'..=b'9' => byte1 - b'0',
            b'a'..=b'f' => byte1 - b'a' + 10,
            b'A'..=b'F' => byte1 - b'A' + 10,
            _ => {
                i += 1;
                continue;
            }
        };

        i += 1;
        if i >= hex_input.len() {
            break;
        }

        let byte2 = hex_input[i];
        let hex2 = match byte2 {
            b'0'..=b'9' => byte2 - b'0',
            b'a'..=b'f' => byte2 - b'a' + 10,
            b'A'..=b'F' => byte2 - b'A' + 10,
            _ => {
                continue;
            }
        };

        output[out_idx] = (hex1 << 4) | hex2;
        out_idx += 1;
        i += 1;
    }

    out_idx
}

fn create_psa_token(writer: &mut impl Write) -> Result<(), TokenError> {
    let mut nonce_hex = [0u8; 64];
    let mut nonce = Aligned32([0u8; 32]);
    let mut token = Aligned32([0u8; 512]);

    loop {
        writeln!(
            writer,
            "\n{{ \"type\": \"enter_nonce\", \"msg\": \"Please enter a hex-encoded nonce (up to 32 bytes):\" }}"
        )
        .map_err(|_| TokenError::WriteError)?;

        let mut i = 0;
        let len = loop {
            let mut c = [0u8; 1];
            let (l, stat) = Console::read(&mut c);
            if stat.is_err() {
                return emit_json_error(writer, "console_read", TokenError::ConsoleRead);
            }
            if l == 1 {
                let byte = c[0];
                if byte == b'\n' || byte == b'\r' {
                    break i;
                } else {
                    if i < nonce_hex.len() {
                        nonce_hex[i] = byte;
                    }
                    i += 1;
                }
            }
        };

        if len != 64 {
            writeln!(
                writer,
                "{{\"type\":\"error\",\"msg\":\"Nonce-Read Failed\"}}"
            )
            .map_err(|_| TokenError::WriteError)?;
            continue;
        }

        // Parse hex string to binary
        let parsed_len = parse_hex(&nonce_hex[..len], &mut nonce.0);
        if parsed_len != 32 {
            writeln!(
                writer,
                "{{\"type\":\"error\",\"msg\":\"Nonce-Parse Failed\"}}"
            )
            .map_err(|_| TokenError::WriteError)?;
            continue;
        }
        break;
    }

    let challenge_len = 32;

    if SpeDriver::<TockSyscalls>::exists().is_err() {
        return emit_json_error(
            writer,
            "spe_driver_not_available",
            TokenError::SpeDriverNotAvailable,
        );
    }

    while SpeDriver::<TockSyscalls>::reserve().is_err() {
        TockSyscalls::yield_wait();
    }

    let status = psa_interface::psa_api::psa_initial_attest_get_token::<
        psa_veneer_client::PsaVeneerClient,
    >(&nonce.0[..challenge_len], &mut token.0);

    let _ = SpeDriver::<TockSyscalls>::release();

    let token_len = match status {
        Ok(_) => 512,
        Err(_) => {
            return emit_json_error(
                writer,
                "token_request_failed",
                TokenError::TokenRequestFailed,
            );
        }
    };

    emit_json_ok(writer, &token.0[..token_len], token_len)
}

fn main() {
    run_app();
}

fn run_app() -> ! {
    #[cfg(any(feature = "test_loop_token", feature = "test_negative"))]
    {
        use libtock::alarm::{Alarm, Milliseconds};

        let mut token = Aligned32([0u8; 512]);
        let nonce = Aligned32([0u8; 32]);
        let mut writer = Console::writer();

        unsafe extern "C" {
            fn psa_call_veneer();
        }

        // 1. Initial valid token request
        writeln!(writer, "start-spe-valid").unwrap();
        while spe_driver::SpeDriver::<TockSyscalls>::reserve().is_err() {
            TockSyscalls::yield_wait();
        }

        Alarm::sleep_for(Milliseconds(10)).unwrap();

        let res = psa_interface::psa_api::psa_initial_attest_get_token::<
            psa_veneer_client::PsaVeneerClient,
        >(&nonce.0[..32], &mut token.0);

        let _ = spe_driver::SpeDriver::<TockSyscalls>::release();

        if res.is_ok() {
            writeln!(writer, "Valid token request succeeded").unwrap();
            let _ = emit_json_ok(&mut writer, &token.0, 512);
        } else {
            writeln!(writer, "Valid token request FAILED").unwrap();
        }
        writeln!(writer, "end-spe-valid").unwrap();

        Alarm::sleep_for(Milliseconds(100)).unwrap();

        // 2. Negative test: Access secure memory (runs once)
        writeln!(writer, "start-spe-fail-secure-mem").unwrap();
        while spe_driver::SpeDriver::<TockSyscalls>::reserve().is_err() {
            TockSyscalls::yield_wait();
        }

        Alarm::sleep_for(Milliseconds(10)).unwrap();

        let invalid_secure_addr = (psa_call_veneer as *const () as usize + 0x100) as *mut u8;
        let invalid_secure_buf =
            unsafe { core::slice::from_raw_parts_mut(invalid_secure_addr, 512) };

        let res_sec = psa_interface::psa_api::psa_initial_attest_get_token::<
            psa_veneer_client::PsaVeneerClient,
        >(&nonce.0[..32], invalid_secure_buf);

        let _ = spe_driver::SpeDriver::<TockSyscalls>::release();

        if res_sec.is_err() {
            writeln!(
                writer,
                "Negative test (secure memory) passed: SPM correctly rejected invalid memory"
            )
            .unwrap();
        } else {
            writeln!(
                writer,
                "Negative test (secure memory) FAILED: SPM allowed access"
            )
            .unwrap();
        }
        writeln!(writer, "end-spe-fail-secure-mem").unwrap();

        Alarm::sleep_for(Milliseconds(100)).unwrap();

        // 3. Negative test: Access another process's memory (runs once)
        writeln!(writer, "start-spe-fail-process-mem").unwrap();
        while spe_driver::SpeDriver::<TockSyscalls>::reserve().is_err() {
            TockSyscalls::yield_wait();
        }

        Alarm::sleep_for(Milliseconds(10)).unwrap();

        let sp: usize;
        unsafe {
            core::arch::asm!("mov {}, sp", out(reg) sp);
        }
        let invalid_proc_addr = (sp + APP_STACK_SIZE) as *mut u8;
        let invalid_proc_buf = unsafe { core::slice::from_raw_parts_mut(invalid_proc_addr, 512) };

        let res_proc = psa_interface::psa_api::psa_initial_attest_get_token::<
            psa_veneer_client::PsaVeneerClient,
        >(&nonce.0[..32], invalid_proc_buf);

        let _ = spe_driver::SpeDriver::<TockSyscalls>::release();

        if res_proc.is_err() {
            writeln!(
                writer,
                "Negative test (process memory) passed: SPM correctly rejected invalid memory"
            )
            .unwrap();
        } else {
            writeln!(
                writer,
                "Negative test (process memory) FAILED: SPM allowed access"
            )
            .unwrap();
        }
        writeln!(writer, "end-spe-fail-process-mem").unwrap();

        Alarm::sleep_for(Milliseconds(250)).unwrap();

        // 4. Main loop: Continuously issue valid token requests
        loop {
            writeln!(writer, "start-spe").unwrap();
            while spe_driver::SpeDriver::<TockSyscalls>::reserve().is_err() {
                TockSyscalls::yield_wait();
            }

            Alarm::sleep_for(Milliseconds(10)).unwrap();

            let res = psa_interface::psa_api::psa_initial_attest_get_token::<
                psa_veneer_client::PsaVeneerClient,
            >(&nonce.0[..32], &mut token.0);

            let _ = spe_driver::SpeDriver::<TockSyscalls>::release();

            if res.is_ok() {
                writeln!(writer, "end-spe").unwrap();
            } else {
                writeln!(writer, "Request failed").unwrap();
            }

            Alarm::sleep_for(Milliseconds(250)).unwrap();
        }
    }

    #[cfg(not(any(feature = "test_loop_token", feature = "test_negative")))]
    {
        let mut writer = Console::writer();
        loop {
            let _ = create_psa_token(&mut writer);
        }
    }
}

fn emit_json_error(
    writer: &mut impl Write,
    error: &'static str,
    token_error: TokenError,
) -> Result<(), TokenError> {
    writeln!(writer, "{{\"type\":\"error\",\"msg\":\"{}\"}}", error)
        .map_err(|_| TokenError::WriteError)?;
    Err(token_error)
}

fn emit_json_ok(writer: &mut impl Write, token: &[u8], token_len: usize) -> Result<(), TokenError> {
    write!(
        writer,
        "{{\"type\":\"token_response\",\"token_len\":{},\"token\":\"",
        token_len
    )
    .map_err(|_| TokenError::WriteError)?;
    for b in token.iter() {
        write!(writer, "{:02x}", b).map_err(|_| TokenError::WriteError)?;
    }
    writeln!(writer, "\"}}").map_err(|_| TokenError::WriteError)?;
    Ok(())
}
