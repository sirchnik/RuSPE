#![no_std]
#![no_main]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use psa_interface::status::into_psa_status;
use ruspe_psc3::services::attest::{InitialAttestation, Psc3AttestPlatform};
use spe::{service::Service, spm::spm_ipc::ServiceVectors, spm_api::PsaMsg};

static SERVICE: InitialAttestation<spe::spm_api::IpcPsaClient> =
    InitialAttestation::new(Psc3AttestPlatform::new(Some(0x32007F00)));

#[unsafe(no_mangle)]
pub unsafe extern "C" fn call(msg: *const PsaMsg) -> ! {
    let msg = unsafe { &*msg };
    let status = into_psa_status(SERVICE.call(*msg, &spe::spm_api::SvcApi));
    // stack gets reset by SPM on every call, so we can just exit the process here
    unsafe {
        core::arch::asm!(
            "svc {SVC_PROCESS_EXIT}",
            SVC_PROCESS_EXIT = const spe::spm_api::SVC_PROCESS_EXIT,
            in("r0") status,
            options(noreturn)
        )
    }
}

// External linker symbols for memory initialization
unsafe extern "C" {
    static _rom_start: u8;
    static _rom_limit: u8;
    static _ram_start: u8;
    static _ram_limit: u8;
    static _stack_limit: u8;
    static _stack_top: u8;
}

#[unsafe(link_section = ".vectors")]
#[used]
pub static BASE_VECTORS: ServiceVectors = ServiceVectors {
    version: <InitialAttestation<spe::spm_api::IpcPsaClient>>::VERSION,
    init_entry: spe::service::init,
    call_entry: call,
    rom_start: core::ptr::addr_of!(_rom_start),
    rom_limit: core::ptr::addr_of!(_rom_limit),
    ram_start: core::ptr::addr_of!(_ram_start),
    ram_limit: core::ptr::addr_of!(_ram_limit),
    stack_limit: core::ptr::addr_of!(_stack_limit),
    stack_top: core::ptr::addr_of!(_stack_top),
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
