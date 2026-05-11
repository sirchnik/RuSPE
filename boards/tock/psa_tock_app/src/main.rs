//! An extremely simple libtock-rs example. Register button events.

#![no_main]
#![no_std]

use core::fmt::Write;
use libtock::console::Console;
use libtock::runtime::{TockSyscalls, set_main, stack_size};

mod spe_driver;
use spe_driver::SpeDriver;

set_main! {main}
stack_size! {0x1000}

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
    let mut token = [0u8; 512];

    write!(writer, "\nEnter nonce in hex (up to 64 chars): ")
        .map_err(|_| TokenError::WriteError)?;
    let (len, stat) = Console::read(&mut nonce_hex);
    if stat.is_err() {
        writeln!(writer, "Error reading from console: {:?}", stat)
            .map_err(|_| TokenError::WriteError)?;
        return Err(TokenError::ConsoleRead);
    }

    // Parse hex string to binary
    let mut nonce = [0u8; 32];
    let hex_len = core::cmp::min(len as usize, nonce_hex.len());
    let parsed_len = parse_hex(&nonce_hex[..hex_len], &mut nonce);

    let challenge_len = core::cmp::min(parsed_len, nonce.len());
    writeln!(writer, "Read {} nonce bytes", challenge_len).map_err(|_| TokenError::WriteError)?;

    SpeDriver::<TockSyscalls>::exists().map_err(|e| {
        let _ = writeln!(writer, "SPE driver not available: {:?}", e);
        TokenError::SpeDriverNotAvailable
    })?;

    let token_len = SpeDriver::<TockSyscalls>::initial_attest_get_token_sync(
        &nonce[..challenge_len],
        &mut token,
    )
    .map_err(|e| {
        let _ = writeln!(writer, "SPE token request failed: {:?}", e);
        TokenError::TokenRequestFailed
    })?;

    writeln!(writer, "Token len: {}", token_len).map_err(|_| TokenError::WriteError)?;
    writeln!(writer, "Token:").map_err(|_| TokenError::WriteError)?;
    for b in token[..token_len].iter() {
        write!(writer, "{:02x}", b).map_err(|_| TokenError::WriteError)?;
    }
    Ok(())
}

fn main() {
    let mut writer = Console::writer();

    loop {
        if let Err(e) = create_psa_token(&mut writer) {
            let _ = writeln!(writer, "Token creation failed: {:?}", e);
        }
    }
}
