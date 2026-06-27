// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Cortex-M33 Memory Protection Unit (MPU)

/// User mode access permissions.
#[derive(Copy, Clone, Debug)]
pub enum Permissions {
    ReadWriteExecute,
    ReadWriteOnly,
    ReadExecuteOnly,
    ReadOnly,
    ExecuteOnly,
}

#[derive(Copy, Clone, Default)]
struct RegionConfig {
    rbar: u32,
    rlar: u32,
}

pub struct MpuConfig<const N: usize> {
    regions: [Option<RegionConfig>; N],
}

impl<const N: usize> Default for MpuConfig<N> {
    fn default() -> Self {
        Self { regions: [None; N] }
    }
}

pub struct MPU<const N: usize> {
    // MPU base address for ARMv8-M
    base: *mut u32,
}

// Ensure it implements Send and Sync since it's just a stateless wrapper over a pointer.
unsafe impl<const N: usize> Send for MPU<N> {}
unsafe impl<const N: usize> Sync for MPU<N> {}

impl<const N: usize> MPU<N> {
    const MPU_CTRL: isize = 1; // 0x04 / 4
    const MPU_RNR: isize = 2; // 0x08 / 4
    const MPU_RBAR: isize = 3; // 0x0C / 4
    const MPU_RLAR: isize = 4; // 0x10 / 4
    const MPU_MAIR0: isize = 12; // 0x30 / 4

    /// Creates a new MPU handle.
    ///
    /// # Safety
    /// This function must be used carefully to ensure only one entity manages the MPU.
    pub const unsafe fn new() -> Self {
        Self {
            base: 0xE000ED90 as *mut u32,
        }
    }

    /// Enables the MPU for applications.
    pub fn enable_app_mpu(&self) {
        unsafe {
            // Enable MPU (bit 0), disable during HardFault/NMI (bit 1), enable background region for privileged (bit 2).
            let ctrl = self.base.offset(Self::MPU_CTRL);
            core::ptr::write_volatile(ctrl, 0x05); // PRIVDEFENA=1, HFNMIENA=0, ENABLE=1
        }
    }

    /// Creates a new empty MPU configuration.
    pub fn new_config(&self) -> Result<MpuConfig<N>, ()> {
        Ok(MpuConfig::default())
    }

    /// Allocates an MPU region in the provided configuration.
    pub fn allocate_region(
        &self,
        base: *const u8,
        size: usize,
        permissions: Permissions,
        config: &mut MpuConfig<N>,
    ) -> Result<(), ()> {
        let (access, execute) = match permissions {
            Permissions::ReadWriteExecute => (0b01, 0),
            Permissions::ReadWriteOnly => (0b01, 1),
            Permissions::ReadExecuteOnly => (0b11, 0),
            Permissions::ReadOnly => (0b11, 1),
            Permissions::ExecuteOnly => (0b10, 0),
        };

        // Align start address to 32 bytes
        let base_addr = base as u32;
        if base_addr & 0x1F != 0 {
            return Err(());
        }

        let rbar = (base_addr & !0x1F) | (access << 1) | execute;

        // End address aligned to 32 bytes
        let end_addr = base_addr + size as u32;
        if end_addr & 0x1F != 0 || size < 32 {
            return Err(());
        }

        // ARMv8-M RLAR LIMIT field uses bits [31:5] of the upper inclusive limit.
        let rlar = ((end_addr - 1) & !0x1F) | 1; // EN=1, ATTRINDX=0, PXN=0

        for i in 0..N {
            if config.regions[i].is_none() {
                config.regions[i] = Some(RegionConfig { rbar, rlar });
                return Ok(());
            }
        }

        Err(())
    }

    /// Configures the MPU with the provided region configuration.
    ///
    /// # Safety
    /// Incorrect use can endanger isolation properties.
    pub unsafe fn configure_mpu(&self, config: &MpuConfig<N>) {
        unsafe {
            // Set ATTR0 to Normal Memory, Outer and Inner Non-cacheable (0x44).
            core::ptr::write_volatile(self.base.offset(Self::MPU_MAIR0), 0x44);

            for (i, region_opt) in config.regions.iter().enumerate() {
                core::ptr::write_volatile(self.base.offset(Self::MPU_RNR), i as u32);
                if let Some(region) = region_opt {
                    core::ptr::write_volatile(self.base.offset(Self::MPU_RBAR), region.rbar);
                    core::ptr::write_volatile(self.base.offset(Self::MPU_RLAR), region.rlar);
                } else {
                    core::ptr::write_volatile(self.base.offset(Self::MPU_RBAR), 0);
                    core::ptr::write_volatile(self.base.offset(Self::MPU_RLAR), 0);
                }
            }
        }
    }
}
