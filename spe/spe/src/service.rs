// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::spm_api::{PsaMsg, SpmApi};

pub trait Service<A: SpmApi> {
    fn call(&self, msg: PsaMsg, api: &A) -> Result<(), psa_interface::status::StatusCode>;
    fn init(&mut self, api: &A) -> Result<(), psa_interface::status::StatusCode>;
    fn deinit(&mut self, api: &A) -> Result<(), psa_interface::status::StatusCode>;
}

/// Initialize memory segments for unprivileged service execution.
///
/// # Safety
/// This function must be called as the naked entry point of the service binary
/// before any Rust code is executed. It sets up the stack pointer and
/// clears/copies the BSS and DATA sections respectively.
#[cfg(target_arch = "arm")]
#[unsafe(naked)]
pub unsafe extern "C" fn init() {
    use core::arch::naked_asm;
    unsafe extern "C" {
        static _szero: *const u32;
        static _ezero: *const u32;
        static _sdata: *const u32;
        static _edata: *const u32;
        static _etext: *const u32;
        static _stack_top: *const u32;
    }

    naked_asm!(
        r#"
        // Initialize BSS section (zero out)
        ldr r0, ={szero}        // r0 = start of BSS
        ldr r1, ={ezero}        // r1 = end of BSS
        movs r2, #0             // r2 = 0

    100:
        cmp r0, r1              // compare pointers
        beq 101f            // if equal, done
        stm r0!, {{r2}}         // *(r0++) = r2 (zero word)
        b 100b

    101:

        // Initialize DATA section (copy from ROM to RAM)
        ldr r0, ={sdata}        // r0 = start of data in RAM
        ldr r1, ={edata}        // r1 = end of data in RAM
        ldr r2, ={etext}        // r2 = start of data in ROM

    200:
        cmp r0, r1              // compare pointers
        beq 201f                // if equal, done
        ldm r2!, {{r3}}         // r3 = *(r2++), load from ROM
        stm r0!, {{r3}}         // *(r0++) = r3, store to RAM
        b 200b 

    201:

        // Initialize stack pointer
        ldr sp, ={stack_top}

        movs r0, #0
        svc {SVC_PROCESS_EXIT}
        "#,
        szero = sym _szero,
        ezero = sym _ezero,
        sdata = sym _sdata,
        edata = sym _edata,
        etext = sym _etext,
        stack_top = sym _stack_top,
        SVC_PROCESS_EXIT = const crate::spm_api::SVC_PROCESS_EXIT,
    );
}

#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn init() {
    unimplemented!("init is only implemented for ARM architectures");
}
