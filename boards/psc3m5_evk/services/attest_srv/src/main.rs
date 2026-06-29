#![no_std]
#![no_main]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use psa_interface::status::into_psa_status;
use ruspe_psc3::services::attest::{InitialAttestation, Psc3AttestPlatform};
use spe::{service::Service, spm::FlashProcessVectors, spm_api::PsaMsg};

static SERVICE: InitialAttestation<spe::spm_api::IpcPsaClient> =
    InitialAttestation::new(Psc3AttestPlatform);

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
    static _stack_limit: *const u32;
    static _stack_top: *const u32;
}

/// Minimal thunk placed in service flash. When the service function returns,
/// it branches here via LR. The `svc` traps back to the SPM's SVC handler
/// which re-elevates to privileged mode and returns to the original caller.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn svc_return() {
    use core::arch::naked_asm;
    naked_asm!(
        "svc {SVC_PROCESS_EXIT}",
        SVC_PROCESS_EXIT = const spe::spm_api::SVC_PROCESS_EXIT,
    );
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".vectors")
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static BASE_VECTORS: FlashProcessVectors = FlashProcessVectors {
    version: InitialAttestation::<spe::spm_api::IpcPsaClient>::VERSION,
    init_entry: spe::service::init,
    call_entry: call,
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
