// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]

use core::fmt::Write;
use psa_interface::{psa_api, types::ServiceHandle};
use psa_veneer_client::PsaVeneerClient;

#[repr(align(32))]
struct Aligned32<T>(T);

pub fn run_test(writer: &mut dyn Write) {
    print_version(writer);
    run_attest(writer);
}
fn print_version(writer: &mut dyn Write) {
    let initial_attest_version =
        psa_api::psa_version::<PsaVeneerClient>(ServiceHandle::AttestationService);
    let internal_trusted_storage =
        psa_api::psa_version::<PsaVeneerClient>(ServiceHandle::InternalTrustedStorageService);

    writer
        .write_fmt(format_args!(
            "initial_attest_version: {}\n",
            initial_attest_version
        ))
        .unwrap();
    writer
        .write_fmt(format_args!(
            "internal_trusted_storage: {}\n",
            internal_trusted_storage
        ))
        .unwrap();
}
fn run_attest(writer: &mut dyn Write) {
    let challenge = Aligned32([0u8; 32]);

    let mut token_buf = Aligned32([0u8; 512]);

    psa_api::psa_initial_attest_get_token::<PsaVeneerClient>(&challenge.0, &mut token_buf.0)
        .unwrap();

    let _ = write!(writer, "\r\ntoken_buf: ");

    for b in token_buf.0 {
        let _ = write!(writer, "{:02x}", b);
    }

    let _ = write!(writer, "\r\n");
}

pub unsafe fn set_vector_table_offset(offset: *const ()) {
    // VTOR is at 0xE000ED08
    unsafe { core::ptr::write_volatile(0xE000ED08 as *mut u32, offset as u32) };
}

pub unsafe extern "C" fn unhandled_interrupt() {
    use core::arch::asm;
    let mut interrupt_number: u32;
    unsafe {
        asm!(
            "mrs {}, ipsr",
            out(reg) interrupt_number,
            options(nomem, nostack, preserves_flags),
        );
    }
    interrupt_number &= 0x1ff;
    panic!("Unhandled Interrupt. ISR {} is active.", interrupt_number);
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn initialize_ram_jump_to_test_main() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    ldr r0, ={sbss}
    ldr r1, ={ebss}
    movs r2, #0

100:
    cmp r1, r0
    beq 101f
    stm r0!, {{r2}}
    b 100b

101:
    ldr r0, ={sdata}
    ldr r1, ={edata}
    ldr r2, ={etext}

200:
    cmp r1, r0
    beq 201f
    ldm r2!, {{r3}}
    stm r0!, {{r3}}
    b 200b

201:
    bl main
        ",
        sbss = sym _szero,
        ebss = sym _ezero,
        sdata = sym _srelocate,
        edata = sym _erelocate,
        etext = sym _etext,
    );
}

unsafe extern "C" {
    static _szero: *const u32;
    static _ezero: *const u32;
    static _etext: *const u32;
    static _srelocate: *const u32;
    static _erelocate: *const u32;
}
