// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

//! Secure startup and services — IPC model with embedded service processes.

#![no_std]
#![no_main]
#![feature(abi_cmse_nonsecure_call)]

use core::ptr::addr_of_mut;

use helpers::static_init;
use kernel::platform::mpu::{MPU as MpuTrait, Permissions};
use spe::{
    psa::psa_api,
    spm::{self, FlashProcess, FlashProcessVectors, IpcProcessPlatform, SpmPlatform},
};
use tock_psc3::{chip, chip_init, gpio, icache, peri_clk, scb};

use psa_interface::types::ServiceHandle;
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

mod arch_v7m;
mod io;
mod startup;

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
}

fn region_len(start: *const u8, limit: *const u8, name: &str) -> usize {
    (limit as usize)
        .checked_sub(start as usize)
        .unwrap_or_else(|| panic!("invalid {name} bounds"))
}

unsafe fn configure_process_mpu(vectors: &FlashProcessVectors) {
    let mpu = unsafe { cortexm33::mpu::new::<8>() };
    let mut config = mpu.new_config().expect("MPU config slots exhausted");

    let service_rom_start = vectors.rom_start;
    let service_rom_size = region_len(vectors.rom_start, vectors.rom_limit, "ROM");
    let service_ram_start = vectors.ram_start;
    let service_ram_size = region_len(vectors.ram_start, vectors.ram_limit, "RAM");
    let ns_ram_start = 0x2400_4000 as *const u8;
    let ns_ram_size = region_len(ns_ram_start, 0x2400_F000 as *const u8, "NS RAM");
    let cryptolite_trng_start = 0x4223_0000 as *const u8;
    let cryptolite_trng_size = 0x200;

    mpu.allocate_region(
        service_rom_start,
        service_rom_size,
        service_rom_size,
        Permissions::ReadExecuteOnly,
        &mut config,
    )
    .expect("MPU ROM region allocation failed");

    mpu.allocate_region(
        service_ram_start,
        service_ram_size,
        service_ram_size,
        Permissions::ReadWriteOnly,
        &mut config,
    )
    .expect("MPU RAM region allocation failed");

    mpu.allocate_region(
        ns_ram_start,
        ns_ram_size,
        ns_ram_size,
        Permissions::ReadOnly,
        &mut config,
    )
    .expect("MPU NS RAM region allocation failed");

    mpu.allocate_region(
        cryptolite_trng_start,
        cryptolite_trng_size,
        cryptolite_trng_size,
        Permissions::ReadWriteOnly,
        &mut config,
    )
    .expect("MPU CRYPTOLITE TRNG region allocation failed");

    let efuse_ctl3_start = 0x4261_0000 as *const u8;
    let efuse_ctl3_size = 0x1000; // size of efuse_ctl3 is only 0x4

    mpu.allocate_region(
        efuse_ctl3_start,
        efuse_ctl3_size,
        efuse_ctl3_size,
        Permissions::ReadOnly,
        &mut config,
    )
    .expect("MPU EFUSE CTL3 region allocation failed");

    unsafe {
        mpu.configure_mpu(&config);
    }
    mpu.enable_app_mpu();
}

impl IpcProcessPlatform for Psc3IpcPlatform {
    fn prepare_process(&self, vectors: &FlashProcessVectors) {
        unsafe {
            configure_process_mpu(vectors);
        }
    }
}

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

    configure_security();

    // Attest service binary is placed in its dedicated secure flash slot.
    // Its vector table (FlashProcessVectors) is at the start of its ROM region.
    const ATTEST_VECTORS: *const FlashProcessVectors = 0x3201_0000 as *const FlashProcessVectors;

    let processes: [FlashProcess; 1] = [FlashProcess::new(
        ServiceHandle::AttestationService,
        ATTEST_VECTORS,
    )];

    let platform = unsafe { static_init!(Psc3IpcPlatform, Psc3IpcPlatform) };

    let spm = unsafe {
        static_init!(
            spm::SpmIpc<Psc3IpcPlatform, 1, FlashProcess>,
            spm::SpmIpc::new(platform, processes)
        )
    };

    psa_api::set_spm(spm);

    io::debugln(format_args!("Init SPE (IPC) done, jumping to non-secure"));

    #[cfg(all(target_arch = "arm", target_os = "none"))]
    unsafe {
        const NONSECURE_START_FLASH: *const [u32; 2] = 0x2201_4000 as *const [u32; 2];
        let [nonsecure_sp, nonsecure_reset] = NONSECURE_START_FLASH.read_volatile();

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
