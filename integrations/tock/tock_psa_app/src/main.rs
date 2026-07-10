// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! An extremely simple libtock-rs example. Register button events.

#![no_main]
#![no_std]
#![allow(dead_code)]

use core::fmt::Write;

use libtock::console::Console;
use libtock::runtime::{TockSyscalls, set_main, stack_size};

mod spe_driver;
use spe_driver::SpeDriver;

set_main! {main}
stack_size! {0x400}

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
    let mut nonce = [0u8; 32];
    let mut token = [0u8; 512];

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
        let parsed_len = parse_hex(&nonce_hex[..len], &mut nonce);
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

    let token_len = match SpeDriver::<TockSyscalls>::initial_attest_get_token_sync(
        &nonce[..challenge_len],
        &mut token,
    ) {
        Ok(token_len) => token_len,
        Err(_) => {
            return emit_json_error(
                writer,
                "token_request_failed",
                TokenError::TokenRequestFailed,
            );
        }
    };

    emit_json_ok(writer, &token[..token_len], token_len)
}

fn main() {
    run_app();
}

fn jump_to_spe() -> ! {
    // TODO prevent jump to secure from non-privileged

    unsafe { core::arch::asm!("nop") }

    unsafe {
        // with tumb bit!
        let func: extern "C" fn() = core::mem::transmute(0x3201ff01usize);
        func();
    }
    loop {
        use libtock::platform::Syscalls;

        TockSyscalls::yield_wait();
    }
}

fn run_app() -> ! {
    #[cfg(feature = "test_unpriv_spe")]
    jump_to_spe();

    #[cfg(feature = "test_loop_token")]
    {
        let mut token = [0u8; 512];
        let nonce = [0u8; 32];
        let mut writer = Console::writer();
        loop {
            use libtock::alarm::{Alarm, Milliseconds};

            writeln!(writer, "start-spe").unwrap();
            let res =
                SpeDriver::<TockSyscalls>::initial_attest_get_token_sync(&nonce[..32], &mut token);

            unsafe {
                core::arch::asm!("nop");
            }

            if res.is_err() {
                writeln!(writer, "Request failed").unwrap();
                continue;
            };
            writeln!(writer, "end-spe").unwrap();
            Alarm::sleep_for(Milliseconds(250)).unwrap();
        }
    }

    #[cfg(not(any(feature = "test_unpriv_spe", feature = "test_loop_token")))]
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
