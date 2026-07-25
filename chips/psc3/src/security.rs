// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cortex_m::sau;

use crate::ppc::{self, PpcRegion};

type RegionId = u16;

const PPC_REGION_COUNT: usize = 222;
const NS_ATTR_REG_COUNT: usize = PPC_REGION_COUNT.div_ceil(32);
const PC_MASK_REG_COUNT: usize = PPC_REGION_COUNT.div_ceil(4);
const REGIONS_PER_ATTR_REG: usize = 32;
const REGIONS_PER_PC_MASK_REG: usize = 4;
const FULL_PC_CONTEXT_MASK: u8 = 0xFF;

// Policy: all regions are non-secure except this allowlist of secure-only
// regions.
const NS_SECURE_ONLY_REGIONS: [RegionId; 1] = [PpcRegion::ProtScb0 as RegionId];
// Policy: only these non-secure regions are non-privileged.
const NS_UNPRIVILEGED_REGIONS: [RegionId; 2] = [
    PpcRegion::ProtCryptoliteTrng as RegionId,
    PpcRegion::ProtEfuseCtl3 as RegionId,
];
// Policy: all regions get PC=0xFF except these exclusions.
const PC_MASK_EXCLUDED_REGIONS: [RegionId; 3] = [
    PpcRegion::ProtCryptoliteTrng as RegionId,
    PpcRegion::ProtEfuseCtl3 as RegionId,
    PpcRegion::ProtScb0 as RegionId,
];

const fn contains_region(values: &[RegionId], needle: RegionId) -> bool {
    let mut i = 0;
    while i < values.len() {
        if values[i] == needle {
            return true;
        }
        i += 1;
    }
    false
}

const fn set_region_bit(mask: &mut [u32; NS_ATTR_REG_COUNT], region: RegionId) {
    let idx = region as usize;
    if idx < PPC_REGION_COUNT {
        let reg = idx / REGIONS_PER_ATTR_REG;
        let bit = idx % REGIONS_PER_ATTR_REG;
        mask[reg] |= 1u32 << bit;
    }
}

const fn clear_region_bit(mask: &mut [u32; NS_ATTR_REG_COUNT], region: RegionId) {
    let idx = region as usize;
    if idx < PPC_REGION_COUNT {
        let reg = idx / REGIONS_PER_ATTR_REG;
        let bit = idx % REGIONS_PER_ATTR_REG;
        mask[reg] &= !(1u32 << bit);
    }
}

const fn build_full_ns_attr_mask() -> [u32; NS_ATTR_REG_COUNT] {
    let mut attrs = [0u32; NS_ATTR_REG_COUNT];
    let mut region = 0;
    while region < PPC_REGION_COUNT {
        set_region_bit(&mut attrs, region as RegionId);
        region += 1;
    }
    attrs
}

const fn build_ns_attrs() -> [u32; NS_ATTR_REG_COUNT] {
    let mut attrs = build_full_ns_attr_mask();

    let mut i = 0;
    while i < NS_SECURE_ONLY_REGIONS.len() {
        clear_region_bit(&mut attrs, NS_SECURE_ONLY_REGIONS[i]);
        i += 1;
    }

    attrs
}

const fn build_ns_p_attrs() -> [u32; NS_ATTR_REG_COUNT] {
    let mut attrs = [0u32; NS_ATTR_REG_COUNT];
    let mut i = 0;
    while i < NS_UNPRIVILEGED_REGIONS.len() {
        set_region_bit(&mut attrs, NS_UNPRIVILEGED_REGIONS[i]);
        i += 1;
    }
    attrs
}

const fn build_pc_masks() -> [u32; PC_MASK_REG_COUNT] {
    let mut masks = [0u32; PC_MASK_REG_COUNT];
    let full_word = u32::from_ne_bytes([
        FULL_PC_CONTEXT_MASK,
        FULL_PC_CONTEXT_MASK,
        FULL_PC_CONTEXT_MASK,
        FULL_PC_CONTEXT_MASK,
    ]);

    let mut reg_idx = 0;
    while reg_idx < PC_MASK_REG_COUNT {
        let mut value = full_word;
        let mut slot = 0;
        while slot < REGIONS_PER_PC_MASK_REG {
            let region = reg_idx * REGIONS_PER_PC_MASK_REG + slot;
            if region >= PPC_REGION_COUNT
                || contains_region(&PC_MASK_EXCLUDED_REGIONS, region as RegionId)
            {
                value &= !(0xFFu32 << (slot * 8));
            }
            slot += 1;
        }
        masks[reg_idx] = value;
        reg_idx += 1;
    }

    masks
}

/// Precomputed at compile time from the region constants above.
const NS_ATTRS: [u32; NS_ATTR_REG_COUNT] = build_ns_attrs();
/// Precomputed at compile time from the region constants above.
const NS_P_ATTRS: [u32; NS_ATTR_REG_COUNT] = build_ns_p_attrs();
/// Precomputed at compile time from the region constants above.
const PC_MASKS: [u32; PC_MASK_REG_COUNT] = build_pc_masks();

/// Configures the security settings for the platform.
///
/// # Errors
///
/// Returns `Err(SauError)` if SAU region configuration fails.
#[inline(never)]
pub fn configure_security(
    nonsecure_flash_start: u32,
    nonsecure_flash_limit: u32,
    nonsecure_ram_start: u32,
    nonsecure_ram_limit: u32,
) -> Result<(), sau::SauError> {
    let nsc_start = nonsecure_flash_start
        .wrapping_add(0x1000_0000)
        .wrapping_sub(0x100);

    // Sometimes while debugging no BUS_ERROR is generated and the debugger just
    // hangs. Change to RZWI then.
    ppc::set_viloation_response(ppc::PPC_CTL::RESP_CFG::BUS_ERROR);

    ppc::configure_bulk_ns_attrs(&NS_ATTRS, &NS_P_ATTRS);
    ppc::configure_bulk_pc_masks(&PC_MASKS);

    ppc::lock_protection_contexts();

    let mut sau = sau::new();

    // SAFETY: We are configuring the SAU memory boundaries correctly for the PSC3m5
    // system.
    unsafe {
        sau.set_region(
            0,
            sau::SauRegion {
                base_address: nonsecure_flash_start,
                limit_address: nonsecure_flash_limit,
                attribute: sau::SauRegionAttribute::NonSecure,
            },
        )?;

        sau.set_region(
            1,
            sau::SauRegion {
                base_address: nsc_start,
                limit_address: nsc_start + 0xFF,
                attribute: sau::SauRegionAttribute::NonSecureCallable,
            },
        )?;

        sau.set_region(
            2,
            sau::SauRegion {
                base_address: nonsecure_ram_start,
                limit_address: nonsecure_ram_limit,
                attribute: sau::SauRegionAttribute::NonSecure,
            },
        )?;

        sau.set_region(
            3,
            sau::SauRegion {
                base_address: 0x2400_F000,
                limit_address: 0x2400_FFFF,
                attribute: sau::SauRegionAttribute::NonSecure,
            },
        )?;

        sau.set_region(
            4,
            sau::SauRegion {
                base_address: 0x4200_0000,
                limit_address: 0x4FFF_FFFF,
                attribute: sau::SauRegionAttribute::NonSecure,
            },
        )?;

        sau.set_region(
            5,
            sau::SauRegion {
                base_address: 0x5202_0000,
                limit_address: 0x5202_637F,
                attribute: sau::SauRegionAttribute::Secure,
            },
        )?;

        sau.set_region(
            6,
            sau::SauRegion {
                base_address: 0x5282_0000,
                limit_address: 0x5282_0FDF,
                attribute: sau::SauRegionAttribute::Secure,
            },
        )?;

        sau.enable();
    }

    Ok(())
}
