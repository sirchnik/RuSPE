// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::spm::FlashProcessVectors;
#[cfg(all(target_arch = "arm", target_os = "none"))]
use kernel::platform::mpu::{MPU as MpuTrait, Permissions, Region};

#[cfg(all(target_arch = "arm", target_os = "none"))]
use cortexm33::mpu;

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

    unsafe {
        MPU_CONFIG = Some(config);
    }
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub unsafe fn configure_process_mpu(_vectors: &FlashProcessVectors) {}

#[cfg(all(target_arch = "arm", target_os = "none"))]
static mut MPU_CONFIG: Option<cortexm33::mpu::CortexMConfig<8>> = None;

#[cfg(all(target_arch = "arm", target_os = "none"))]
static mut MAPPED_VECTORS: [Option<(bool, u32, Region)>; 4] = [None; 4];

#[cfg(all(target_arch = "arm", target_os = "none"))]
pub unsafe fn mpu_map_vec(is_outvec: bool, vec_idx: u32, base: *const u8, size: usize) {
    if size == 0 {
        return;
    }

    let mpu = unsafe { cortexm33::mpu::new::<8>() };
    let config = MPU_CONFIG.as_mut().expect("MPU not configured");

    let base_addr = base as usize;
    let end_addr = base_addr + size;
    let aligned_base = base_addr & !0x1F;
    let aligned_end = (end_addr + 0x1F) & !0x1F;
    let aligned_size = aligned_end - aligned_base;

    let permissions = if is_outvec {
        Permissions::ReadWriteOnly
    } else {
        Permissions::ReadOnly
    };

    let region = mpu
        .allocate_region(
            aligned_base as *const u8,
            aligned_size,
            aligned_size,
            permissions,
            config,
        )
        .expect("Failed to allocate MPU region for IO vector");

    mpu.configure_mpu(config);

    for i in 0..4 {
        if MAPPED_VECTORS[i].is_none() {
            MAPPED_VECTORS[i] = Some((is_outvec, vec_idx, region));
            return;
        }
    }
    panic!("Too many mapped vectors");
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
pub unsafe fn mpu_unmap_vec(is_outvec: bool, vec_idx: u32) {
    let mpu = cortexm33::mpu::new::<8>();
    let config = MPU_CONFIG.as_mut().expect("MPU not configured");

    for i in 0..4 {
        if let Some((mapped_is_outvec, mapped_vec_idx, region)) = MAPPED_VECTORS[i] {
            if mapped_is_outvec == is_outvec && mapped_vec_idx == vec_idx {
                MAPPED_VECTORS[i] = None;
                mpu.remove_memory_region(region, config)
                    .expect("Failed to remove MPU region");
                mpu.configure_mpu(config);
                return;
            }
        }
    }
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub unsafe fn mpu_map_vec(_is_outvec: bool, _vec_idx: u32, _base: *const u8, _size: usize) {}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub unsafe fn mpu_unmap_vec(_is_outvec: bool, _vec_idx: u32) {}
