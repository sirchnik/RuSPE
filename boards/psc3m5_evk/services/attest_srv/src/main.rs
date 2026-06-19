#![no_std]
#![no_main]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use ruspe_psc3::services::attest::{InitialAttestation, Psc3AttestPlatform};
use psa_interface::status::into_psa_status;
use spe::{spm_api::PsaMsg, service::Service, spm::FlashProcessVectors};

static SERVICE: InitialAttestation = InitialAttestation::new(Psc3AttestPlatform);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn call(msg: *const PsaMsg) -> psa_interface::types::PsaStatus {
    let msg = unsafe { &*msg };
    into_psa_status(SERVICE.call(*msg, &spe::spm_api::SvcApi))
}

// External linker symbols for memory initialization
unsafe extern "C" {
    static _rom_start: *const u32;
    static _rom_limit: *const u32;
    static _ram_start: *const u32;
    static _ram_limit: *const u32;
    static _szero: *const u32;
    static _ezero: *const u32;
    static _sdata: *const u32;
    static _edata: *const u32;
    static _etext: *const u32;
    static _stack_limit: *const u32;
    static _stack_top: *const u32;
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init() {
    use core::arch::naked_asm;
    naked_asm!(
        "
        // Initialize BSS section (zero out)
        ldr r0, ={szero}        // r0 = start of BSS
        ldr r1, ={ezero}        // r1 = end of BSS
        movs r2, #0             // r2 = 0

    bss_loop:
        cmp r0, r1              // compare pointers
        beq bss_done            // if equal, done
        stm r0!, {{r2}}         // *(r0++) = r2 (zero word)
        b bss_loop

    bss_done:

        // Initialize DATA section (copy from ROM to RAM)
        ldr r0, ={sdata}        // r0 = start of data in RAM
        ldr r1, ={edata}        // r1 = end of data in RAM
        ldr r2, ={etext}        // r2 = start of data in ROM

    data_loop:
        cmp r0, r1              // compare pointers
        beq data_done           // if equal, done
        ldm r2!, {{r3}}         // r3 = *(r2++), load from ROM
        stm r0!, {{r3}}         // *(r0++) = r3, store to RAM
        b data_loop

    data_done:

        // Initialize stack pointer
        ldr sp, ={stack_top}

        bx lr
        ",
        szero = sym _szero,
        ezero = sym _ezero,
        sdata = sym _sdata,
        edata = sym _edata,
        etext = sym _etext,
        stack_top = sym _stack_top,
    );
}

/// Minimal thunk placed in service flash. When the service function returns,
/// it branches here via LR. The `svc #0` traps back to the SPM's SVC handler
/// which re-elevates to privileged mode and returns to the original caller.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn svc_return() {
    use core::arch::naked_asm;
    naked_asm!("svc #0");
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".vectors")
)]
// used Ensures that the symbol is kept until the final binary
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static BASE_VECTORS: FlashProcessVectors = FlashProcessVectors {
    init,
    call,
    rom_start: unsafe { &_rom_start as *const _ as *const u8 },
    rom_limit: unsafe { &_rom_limit as *const _ as *const u8 },
    ram_start: unsafe { &_ram_start as *const _ as *const u8 },
    ram_limit: unsafe { &_ram_limit as *const _ as *const u8 },
    svc_return,
    stack_limit: unsafe { &_stack_limit as *const _ as *const u8 },
    stack_top: unsafe { &_stack_top as *const _ as *const u8 },
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
