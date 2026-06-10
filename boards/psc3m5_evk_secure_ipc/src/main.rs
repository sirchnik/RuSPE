// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Secure startup and services — IPC model with embedded service processes.

#![no_std]
#![no_main]
#![feature(abi_cmse_nonsecure_call)]

use core::ptr::addr_of_mut;

use helpers::static_init;
use spe::{
    psa::psa_api,
    spm::{
        self, CustomMpuRegion, FlashProcess, FlashProcessVectors, IpcProcessPlatform, Permissions,
        SpmPlatform,
    },
};
use tock_psc3::{chip, chip_init, gpio, icache, peri_clk, scb};

use ruspe_psc3::configure_security;

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

mod faults;
mod io;
mod startup;
mod svc;

const NONSECURE_FLASH_START: u32 = 0x2202_0000;
const NONSECURE_FLASH_LIMIT: u32 = 0x2203_FFFF;
const NONSECURE_RAM_START: u32 = 0x2400_5100;
const NONSECURE_RAM_LIMIT: u32 = 0x2400_EFFF;

/// Minimal platform for the IPC model — only provides memory permission checks.
/// Service dispatch is handled by the SpmIpc process table, not by this platform.
pub struct Psc3IpcPlatform;

impl SpmPlatform for Psc3IpcPlatform {
    fn call(&self, _msg: spe::psa::psa_call::PsaMsg) -> Result<(), spe::StatusCode> {
        // In the IPC model, services are dispatched via the process table.
        // This method is never called directly.
        Err(spe::StatusCode::NotSupported)
    }

    fn has_permission_on_memory(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: spe::psa::psa_call::CallerAttributes,
    ) -> bool {
        // TODO find something better
        return true;
        use ruspe_cortexm::cmse;

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
            if caller.ns {
                if is_write {
                    target.ns_read_and_writable()
                } else {
                    target.ns_readable()
                }
            } else {
                if is_write {
                    target.read_and_writable()
                } else {
                    target.readable()
                }
            }
        } else {
            false
        }
    }
    fn custom_mpu_regions(
        &self,
        handle: psa_interface::types::ServiceHandle,
    ) -> &[CustomMpuRegion] {
        if (handle as isize) == (psa_interface::types::ServiceHandle::AttestationService as isize) {
            static REGIONS: [CustomMpuRegion; 2] = [
                CustomMpuRegion {
                    base: 0x4223_0000 as *const u8,
                    size: 0x200,
                    permissions: Permissions::ReadWriteOnly,
                },
                CustomMpuRegion {
                    base: 0x4261_0180 as *const u8,
                    size: 0x20,
                    permissions: Permissions::ReadOnly,
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
    icache::sys_init_enable_cache();
    chip_init::preinit_peripherals();
    chip_init::init_system();
    peri_clk::enable_scb0();

    chip::init_gpio_pins();

    let scb0 = unsafe { static_init!(scb::Scb, scb::Scb::new_scb0()) };

    scb0.set_standard_uart_mode();
    scb0.enable_scb();

    unsafe {
        (*addr_of_mut!(io::WRITER)).set_serial(scb0);

        cortexm33::nvic::set_interrupt_non_secure(0, 140);
        cortexm33::nvic::enable_all();
    }

    // set msplim. There was one incident where then non-secure handled stack overflow.
    cortexm33::support::set_msplim(core::ptr::addr_of!(_sstack) as u32);

    unsafe {
        let aircr = 0xe000ed0c as *mut u32;
        let mut value = aircr.read_volatile();
        value &= 0x0 << 16; // Clear VECTKEY
        aircr.write_volatile(value);
        value |= 0x5fa << 16; // VECTKEY
        value |= 1 << 4; // SYSRESETREQS: allow reset request only from secure
        value |= 1 << 13; // BFHFNMINS: allow hardfault, busfault, nmi handled in non-secure
        aircr.write_volatile(value);
    }

    let gpio = gpio::PsocPins::new(true);

    const GPIO_CONFIG: gpio::PreConfig = gpio::PreConfig {
        out_val: 1,
        drive_mode: gpio::DriveMode::PullUp,
        hsiom: gpio::HsiomFunction::GPIOControlsOut,
        int_edge: false,
        int_mask: 0,
        vtrip: 0,
        fast_slew_rate: true,
        drive_sel: gpio::DriveSelect::Half,
        vreg_en: false,
        ibuf_mode: 0,
        vtrip_sel: 0,
        vref_sel: 0,
        voh_sel: 0,
        non_sec: true,
    };

    gpio.get_pin(gpio::PsocPin::P8_5).preconfigure(&GPIO_CONFIG);
    let led_pin = gpio.get_pin(gpio::PsocPin::P8_4);
    led_pin.preconfigure(&GPIO_CONFIG);

    configure_security(
        NONSECURE_FLASH_START,
        NONSECURE_FLASH_LIMIT,
        NONSECURE_RAM_START,
        NONSECURE_RAM_LIMIT,
    );

    // Service binaries are placed in dedicated secure flash slots.
    // Vector tables (FlashProcessVectors) are at the start of each service's ROM region.
    // Addresses and handles are generated at build time from board task settings.

    // Load service configuration generated at build time and build the exact process table.
    let processes: [FlashProcess; service_config::SERVICE_COUNT] = core::array::from_fn(|i| {
        FlashProcess::new(
            service_config::SERVICE_HANDLES[i],
            service_config::SERVICE_ADDRS[i] as *const FlashProcessVectors,
        )
    });

    let platform = unsafe { static_init!(Psc3IpcPlatform, Psc3IpcPlatform) };

    let spm = unsafe {
        static_init!(
            spm::SpmIpc<Psc3IpcPlatform, { service_config::SERVICE_COUNT }, FlashProcess>,
            spm::SpmIpc::new(platform, processes)
        )
    };

    psa_api::set_spm(spm);

    io::debugln(format_args!("Init SPE (IPC) done, jumping to non-secure"));

    unsafe {
        let nonsecure_start_flash = NONSECURE_FLASH_START as *const [u32; 2];
        let [nonsecure_sp, nonsecure_reset] = nonsecure_start_flash.read_volatile();

        // Set non-secure main stack pointer
        core::arch::asm!(
            "msr msp_ns, {nonsecure_sp}",
            nonsecure_sp = in(reg) nonsecure_sp,
            options(nomem, nostack, preserves_flags),
        );

        let nonsecure_reset = core::mem::transmute::<*const u32, extern "cmse-nonsecure-call" fn()>(
            nonsecure_reset as *const u32,
        );

        nonsecure_reset();
    }
}
