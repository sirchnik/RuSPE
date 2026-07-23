// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Secure startup and services - IPC model with embedded service processes.

#![no_std]
#![no_main]
#![feature(cmse_nonsecure_entry)]
#![feature(abi_cmse_nonsecure_call)]

use core::ptr::addr_of_mut;

use cortex_m::mpu::Permissions;
use helpers::static_init;
use ruspe_psc3::configure_security;
use spe::spm;
use spe::spm::spm_ipc::{
    CustomMpuRegion, IpcPlatform, IpcProcessPlatform, ServiceProcess, ServiceVectors,
};
use tock_psc3::{chip, chip_init, icache, peri_clk, scb};

unsafe extern "Rust" {
    static __veneer_base: ();
    static __veneer_limit: ();
}

// These symbols are defined in the linker script.
unsafe extern "C" {
    /// Beginning of the stack region.
    static _sstack: u8;
}

mod service_config {
    include!(concat!(env!("OUT_DIR"), "/service_config.rs"));
}

mod io;
mod startup;

#[expect(unexpected_cfgs)]
pub mod global_spm_api {
    spe::define_spm_api!(spe::spm::spm_ipc::SpmIpc<crate::Psc3IpcPlatform, { crate::service_config::SERVICE_COUNT }, spe::spm::spm_ipc::ServiceProcess>);
}

const NONSECURE_FLASH_START: u32 = 0x2202_0000;
const NONSECURE_FLASH_LIMIT: u32 = 0x2203_FFFF;
const NONSECURE_RAM_START: u32 = 0x2400_5100;
const NONSECURE_RAM_LIMIT: u32 = 0x2400_EFFF;

/// Minimal platform for the IPC model - only provides memory permission checks.
/// Service dispatch is handled by the SpmIpc process table, not by this
/// platform.
pub struct Psc3IpcPlatform;

impl IpcPlatform for Psc3IpcPlatform {
    fn has_permission_on_memory(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: spe::spm_api::CallerAttributes,
    ) -> bool {
        use cortex_m::cmse;

        if len == 0 {
            return true;
        }

        if base.is_null() {
            return false;
        }

        let access_type = match (caller.ns, caller.privileged) {
            (true, false) => cmse::AccessType::NonSecureUnprivileged,
            (true, true) => cmse::AccessType::NonSecure,
            (false, false) => cmse::AccessType::Unprivileged,
            (false, true) => cmse::AccessType::Current,
        };

        if let Some(target) = cmse::TestTarget::check_range(base as *mut u32, len, access_type) {
            let is_security_state_valid = if caller.ns {
                !target.secure()
            } else {
                target.secure()
            };

            let has_permission = if is_write {
                target.read_and_writable()
            } else {
                target.readable()
            };

            is_security_state_valid && has_permission
        } else {
            false
        }
    }

    fn custom_mpu_regions(
        &self,
        handle: psa_interface::types::ServiceHandle,
    ) -> &[CustomMpuRegion] {
        if (handle as isize) == (psa_interface::types::ServiceHandle::AttestationService as isize) {
            const REGIONS: [CustomMpuRegion; 3] = [
                CustomMpuRegion {
                    base: 0x4223_0000 as *const u8,
                    size: 0x200,
                    permissions: Permissions::ReadWriteXN,
                },
                CustomMpuRegion {
                    base: 0x4261_0180 as *const u8,
                    size: 0x20,
                    permissions: Permissions::ReadXN,
                },
                CustomMpuRegion {
                    base: 0x3200_7F00 as *const u8,
                    size: 0x100,
                    permissions: Permissions::ReadXN,
                },
            ];
            &REGIONS
        } else {
            &[]
        }
    }
}

impl IpcProcessPlatform for Psc3IpcPlatform {}

#[unsafe(no_mangle)]
pub unsafe fn main() {
    let nonsecure_reset = unsafe { start() };
    nonsecure_reset();
}

/// Separated initialization function to ensure its stack frame is popped
/// before jumping to the non-secure entry point in `main`.
/// Returns the non-secure reset handler address.
#[inline(never)]
unsafe fn start() -> extern "cmse-nonsecure-call" fn() {
    icache::sys_init_enable_cache();
    chip_init::preinit_peripherals();
    chip_init::init_system();
    peri_clk::enable_scb0();

    chip::configure_gpio_secure_states();
    chip::init_scb0_uart_pins();

    let scb0 = unsafe { static_init!(scb::Scb, scb::Scb::new_scb0()) };

    scb0.set_standard_uart_mode();
    scb0.enable_scb();

    unsafe {
        (*addr_of_mut!(io::WRITER)).set_serial(scb0);

        cortex_m::nvic::set_interrupt_non_secure(0, 140);
        cortex_m::nvic::enable_all();
    }

    // set msplim. There was one incident where then non-secure handled stack
    // overflow.
    unsafe {
        let stack_base = core::ptr::addr_of!(_sstack) as *mut u32;
        cortex_m::register::set_msplim(stack_base as u32);
    }

    unsafe {
        spe::startup::configure_aircr();
    }

    configure_security(
        NONSECURE_FLASH_START,
        NONSECURE_FLASH_LIMIT,
        NONSECURE_RAM_START,
        NONSECURE_RAM_LIMIT,
    );

    // Service binaries are placed in dedicated secure flash slots.
    // Vector tables (ServiceVectors) are at the start of each service's ROM region.
    // Addresses and handles are generated at build time from board task settings.

    // Load service configuration generated at build time and build the exact
    // process table.
    let processes: [ServiceProcess; service_config::SERVICE_COUNT] =
        core::array::from_fn(|i| unsafe {
            ServiceProcess::new(
                service_config::SERVICE_HANDLES[i],
                &*(service_config::SERVICE_ADDRS[i] as *const ServiceVectors),
            )
        });

    let platform = unsafe { static_init!(Psc3IpcPlatform, Psc3IpcPlatform) };

    let spm = unsafe {
        static_init!(
            spm::spm_ipc::SpmIpc<Psc3IpcPlatform, { service_config::SERVICE_COUNT }, ServiceProcess>,
            spm::spm_ipc::SpmIpc::new(platform, processes)
        )
    };

    let _ = global_spm_api::SPM.try_set(spm);

    io::debugln(format_args!("Init SPE (IPC) done, jumping to non-secure"));

    unsafe { spe::startup::jump_to_nonsecure(NONSECURE_FLASH_START) }
}
