#![no_std]
#![no_main]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use psa_interface::status::into_psa_status;
use ruspe_psc3::services::crypto::Crypto;
use spe::service::Service;
use spe::spm::spm_ipc::ServiceVectors;
use spe::spm_api::PsaMsg;

static SERVICE: Crypto = Crypto::new([
    0xc3, 0xfe, 0xe8, 0x4c, 0x73, 0x49, 0xd8, 0xe8, 0x44, 0x3d, 0xe4, 0xae, 0x65, 0xf7, 0xea, 0x3b,
    0xb8, 0x09, 0x3b, 0xe9, 0xb1, 0x5b, 0xc4, 0xbd, 0x4a, 0x54, 0x95, 0x3c, 0xd3, 0x31, 0xce, 0x1b,
]);

/// # Safety
///
/// This function must only be called by the SPM via the service vector table.
/// The caller must ensure that the `msg` pointer is valid, properly aligned,
/// and points to readable memory containing a valid `PsaMsg`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn call(msg: *const PsaMsg) -> ! {
    let msg_bytes =
        unsafe { core::slice::from_raw_parts(msg as *const u8, core::mem::size_of::<PsaMsg>()) };
    let msg = *bytemuck::checked::from_bytes::<PsaMsg>(msg_bytes);
    let status = into_psa_status(SERVICE.call(msg, &spe::spm_api::SvcApi));
    // stack gets reset by SPM on every call, so we can just exit the process here
    spe::spm_api::process_exit(status);
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
    version: <Crypto>::VERSION,
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
