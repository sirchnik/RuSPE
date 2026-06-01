// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::spm::FlashProcessVectors;

#[cfg(all(target_arch = "arm", target_os = "none"))]
use cortexm33::mpu;
#[cfg(all(target_arch = "arm", target_os = "none"))]
use kernel::platform::mpu::{MPU as MpuTrait, Permissions};

#[cfg(all(target_arch = "arm", target_os = "none"))]
fn region_len(start: *const u8, limit: *const u8, name: &str) -> usize {
    (limit as usize)
        .checked_sub(start as usize)
        .unwrap_or_else(|| panic!("invalid {name} bounds"))
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
pub unsafe fn configure_process_mpu(vectors: &FlashProcessVectors) {
    let mpu = unsafe { mpu::new::<8>() };
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

    let efuse_ctl3_start = 0x4261_0180 as *const u8;
    let efuse_ctl3_size = 0x20;

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

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub unsafe fn configure_process_mpu(_vectors: &FlashProcessVectors) {}
