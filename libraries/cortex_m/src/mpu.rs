// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Cortex-M33 Memory Protection Unit (MPU)

use tock_registers::interfaces::{ReadWriteable as _, Writeable as _};
use tock_registers::registers::{ReadOnly, ReadWrite};
use tock_registers::{register_bitfields, register_structs};

/// User mode access permissions.
#[derive(Copy, Clone, Debug)]
pub enum Permissions {
    ReadWriteExecute,
    ReadWriteXN,
    ReadXN,
    ReadExecute,
    ReadPrivXN,
    ReadPrivExecute,
}

/// Errors that can occur during MPU operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpuError {
    /// The base or limit address is not properly aligned to 32 bytes.
    AddressNotAligned,
    /// The size of the region is too small (less than 32 bytes).
    SizeTooSmall,
    /// There are no available MPU regions to allocate.
    NoRegionsAvailable,
}

register_structs! {
    /// MPU Registers for the Armv8-M architecture
    pub MpuRegisters {
        /// MPU Type Register
        (0x0000 => mpu_type: ReadOnly<u32, MPU_TYPE::Register>),
        /// MPU Control Register
        (0x0004 => ctrl: ReadWrite<u32, MPU_CTRL::Register>),
        /// MPU Region Number Register
        (0x0008 => rnr: ReadWrite<u32, MPU_RNR::Register>),
        /// MPU Region Base Address Register
        (0x000C => rbar: ReadWrite<u32, MPU_RBAR::Register>),
        /// MPU Region Limit Address Register
        (0x0010 => rlar: ReadWrite<u32, MPU_RLAR::Register>),
        /// MPU Region Base Address Register Alias 1
        (0x0014 => rbar_a1: ReadWrite<u32, MPU_RBAR_A1::Register>),
        /// MPU Region Limit Address Register Alias 1
        (0x0018 => rlar_a1: ReadWrite<u32, MPU_RLAR_A1::Register>),
        /// MPU Region Base Address Register Alias 2
        (0x001C => rbar_a2: ReadWrite<u32, MPU_RBAR_A2::Register>),
        /// MPU Region Limit Address Register Alias 2
        (0x0020 => rlar_a2: ReadWrite<u32, MPU_RLAR_A2::Register>),
        /// MPU Region Base Address Register Alias 3
        (0x0024 => rbar_a3: ReadWrite<u32, MPU_RBAR_A3::Register>),
        /// MPU Region Limit Address Register Alias 3
        (0x0028 => rlar_a3: ReadWrite<u32, MPU_RLAR_A3::Register>),
        (0x002c => _reserved0),
        /// MPU Memory Attribute Indirection Register 0
        (0x0030 => mair0: ReadWrite<u32, MPU_MAIR0::Register>),
        /// MPU Memory Attribute Indirection Register 1
        (0x0034 => mair1: ReadWrite<u32, MPU_MAIR1::Register>),
        (0x0038 => @END),
    }
}

register_bitfields![u32,
    MPU_TYPE [
        DREGION OFFSET(8) NUMBITS(8) [],
        SEPARATE OFFSET(0) NUMBITS(1) []
    ],
    MPU_CTRL [
        PRIVDEFENA OFFSET(2) NUMBITS(1) [],
        HFNMIENA OFFSET(1) NUMBITS(1) [],
        ENABLE OFFSET(0) NUMBITS(1) []
    ],
    MPU_RNR [
        REGION OFFSET(0) NUMBITS(8) []
    ],
    MPU_RBAR [
        BASE OFFSET(5) NUMBITS(27) [],
        SH OFFSET(3) NUMBITS(2) [],
        AP OFFSET(1) NUMBITS(2) [
            ReadWritePrivilegedOnly = 0b00,
            ReadWrite = 0b01,
            ReadOnlyPrivilegedOnly = 0b10,
            ReadOnly = 0b11
        ],
        XN OFFSET(0) NUMBITS(1) [
            Disable = 0,
            Enable = 1
        ]
    ],
    MPU_RLAR [
        LIMIT OFFSET(5) NUMBITS(27) [],
        PXN OFFSET(4) NUMBITS(1) [
            Enable = 0,
            Disable = 1
        ],
        ATTRINDX OFFSET(1) NUMBITS(3) [],
        ENABLE OFFSET(0) NUMBITS(1) []
    ],
    MPU_RBAR_A1 [
        BASE OFFSET(5) NUMBITS(27) [],
        SH OFFSET(3) NUMBITS(2) [],
        AP OFFSET(1) NUMBITS(2) [],
        XN OFFSET(0) NUMBITS(1) []
    ],
    MPU_RLAR_A1 [
        LIMIT OFFSET(5) NUMBITS(27) [],
        ATTRINDX OFFSET(1) NUMBITS(3) [],
        EN OFFSET(0) NUMBITS(1) []
    ],
    MPU_RBAR_A2 [
        BASE OFFSET(5) NUMBITS(27) [],
        SH OFFSET(3) NUMBITS(2) [],
        AP OFFSET(1) NUMBITS(2) [],
        XN OFFSET(0) NUMBITS(1) []
    ],
    MPU_RLAR_A2 [
        LIMIT OFFSET(5) NUMBITS(27) [],
        ATTRINDX OFFSET(1) NUMBITS(3) [],
        EN OFFSET(0) NUMBITS(1) []
    ],
    MPU_RBAR_A3 [
        BASE OFFSET(5) NUMBITS(27) [],
        SH OFFSET(3) NUMBITS(2) [],
        AP OFFSET(1) NUMBITS(2) [],
        XN OFFSET(0) NUMBITS(1) []
    ],
    MPU_RLAR_A3 [
        LIMIT OFFSET(5) NUMBITS(27) [],
        ATTRINDX OFFSET(1) NUMBITS(3) [],
        EN OFFSET(0) NUMBITS(1) []
    ],
    MPU_MAIR0 [
        ATTR3 OFFSET(24) NUMBITS(8) [],
        ATTR2 OFFSET(16) NUMBITS(8) [],
        ATTR1 OFFSET(8) NUMBITS(8) [],
        ATTR0 OFFSET(0) NUMBITS(8) []
    ],
    MPU_MAIR1 [
        ATTR7 OFFSET(24) NUMBITS(8) [],
        ATTR6 OFFSET(16) NUMBITS(8) [],
        ATTR5 OFFSET(8) NUMBITS(8) [],
        ATTR4 OFFSET(0) NUMBITS(8) []
    ]
];

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

pub struct Mpu<const N: usize> {
    registers: *const MpuRegisters,
}

impl<const N: usize> Default for Mpu<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Mpu<N> {
    /// Creates a new MPU handle.
    ///
    /// # Safety
    /// This function must be used carefully to ensure only one entity manages
    /// the MPU.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            registers: 0xE000_ED90 as *const MpuRegisters,
        }
    }

    const fn registers(&self) -> &MpuRegisters {
        unsafe { &*self.registers }
    }

    /// Enables the MPU
    ///
    /// # Safety
    /// Incorrect use can endanger isolation properties.
    pub unsafe fn enable_mpu(&self) {
        self.registers()
            .ctrl
            .write(MPU_CTRL::ENABLE::SET + MPU_CTRL::HFNMIENA::CLEAR + MPU_CTRL::PRIVDEFENA::SET);
    }

    /// Allocates an MPU region in the provided configuration.
    ///
    /// # Errors
    /// Returns `Err(MpuError::AddressNotAligned)` if the base or end address
    /// are not properly aligned, `Err(MpuError::SizeTooSmall)` if the size
    /// is less than 32 bytes, or `Err(MpuError::NoRegionsAvailable)` if no
    /// regions are available.
    #[expect(clippy::similar_names, reason = "rbar and rlar are standard register names")]
    pub fn allocate_region(
        &self,
        base: *const u8,
        size: u32,
        permissions: Permissions,
        config: &mut MpuConfig<N>,
    ) -> Result<(), MpuError> {
        let (access, execute) = match permissions {
            Permissions::ReadWriteExecute => (MPU_RBAR::AP::ReadWrite, MPU_RBAR::XN::Enable),
            Permissions::ReadWriteXN => (MPU_RBAR::AP::ReadWrite, MPU_RBAR::XN::Disable),
            Permissions::ReadXN => (MPU_RBAR::AP::ReadOnly, MPU_RBAR::XN::Enable),
            Permissions::ReadExecute => (MPU_RBAR::AP::ReadOnly, MPU_RBAR::XN::Disable),
            Permissions::ReadPrivXN => (MPU_RBAR::AP::ReadOnlyPrivilegedOnly, MPU_RBAR::XN::Enable),
            Permissions::ReadPrivExecute => {
                (MPU_RBAR::AP::ReadOnlyPrivilegedOnly, MPU_RBAR::XN::Disable)
            }
        };

        // Align start address to 32 bytes
        let base_addr = base as u32;
        if base_addr & 0x1F != 0 {
            return Err(MpuError::AddressNotAligned);
        }

        let rbar_val =
            (MPU_RBAR::BASE.val(base_addr >> 5) + MPU_RBAR::SH.val(0) + access + execute).value;

        // End address aligned to 32 bytes
        let end_addr = base_addr + size;
        if size < 32 {
            return Err(MpuError::SizeTooSmall);
        }
        if end_addr & 0x1F != 0 {
            return Err(MpuError::AddressNotAligned);
        }

        // ARMv8-M RLAR LIMIT field uses bits [31:5] of the upper inclusive limit.
        let rlar_val = (MPU_RLAR::ENABLE::SET
            + MPU_RLAR::LIMIT.val((end_addr - 1) >> 5)
            + MPU_RLAR::PXN::Disable
            + MPU_RLAR::ATTRINDX.val(0))
        .value;

        for i in 0..N {
            if config.regions[i].is_none() {
                config.regions[i] = Some(RegionConfig {
                    rbar: rbar_val,
                    rlar: rlar_val,
                });
                return Ok(());
            }
        }

        Err(MpuError::NoRegionsAvailable)
    }

    /// Configures the MPU with the provided region configuration.
    ///
    /// # Safety
    /// Incorrect use can endanger isolation properties.
    pub unsafe fn configure_mpu(&self, config: &MpuConfig<N>) {
        // Set ATTR0 to Normal Memory, Outer and Inner Non-cacheable (0x44).
        self.registers()
            .mair0
            .modify(MPU_MAIR0::ATTR0.val(0b0100_0100));

        for (i, region_opt) in config.regions.iter().enumerate() {
            #[expect(clippy::cast_possible_truncation, reason = "region index fits in u32")] // region len should be below u32
            self.registers().rnr.write(MPU_RNR::REGION.val(i as u32));
            if let Some(region) = region_opt {
                self.registers().rbar.set(region.rbar);
                self.registers().rlar.set(region.rlar);
            } else {
                self.registers().rbar.set(0);
                self.registers().rlar.set(0);
            }
        }
    }
}
