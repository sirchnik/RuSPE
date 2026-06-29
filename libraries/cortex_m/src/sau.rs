// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Security Attribution Unit
//! For reference please check the section B8.3 of the Armv8-M Architecture Reference Manual.

use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::{ReadOnly, ReadWrite};

/// Register block
#[repr(C)]
pub struct SauRegisters {
    /// Control Register
    pub ctrl: ReadWrite<u32, CTRL::Register>,
    /// Type Register
    pub type_reg: ReadOnly<u32, TYPE::Register>,
    /// Region Number Register
    pub rnr: ReadWrite<u32, RNR::Register>,
    /// Region Base Address Register
    pub rbar: ReadWrite<u32, RBAR::Register>,
    /// Region Limit Address Register
    pub rlar: ReadWrite<u32, RLAR::Register>,
    /// Secure Fault Status Register
    pub sfsr: ReadOnly<u32, SFSR::Register>,
    /// Secure Fault Address Register
    pub sfar: ReadOnly<u32, SFAR::Register>,
}

register_bitfields![u32,
    /// Control Register description
    CTRL [
        ENABLE OFFSET(0) NUMBITS(1) [],
        ALLNS OFFSET(1) NUMBITS(1) []
    ],

    /// Type Register description
    TYPE [
        SREGION OFFSET(0) NUMBITS(8) []
    ],

    /// Region Number Register description
    RNR [
        REGION OFFSET(0) NUMBITS(8) []
    ],

    /// Region Base Address Register description
    RBAR [
        BADDR OFFSET(5) NUMBITS(27) []
    ],

    /// Region Limit Address Register description
    RLAR [
        LADDR OFFSET(5) NUMBITS(27) [],
        NSC OFFSET(1) NUMBITS(1) [],
        ENABLE OFFSET(0) NUMBITS(1) []
    ],

    /// Secure Fault Status Register description
    SFSR [
        INVEP OFFSET(0) NUMBITS(1) [],
        INVIS OFFSET(1) NUMBITS(1) [],
        INVER OFFSET(2) NUMBITS(1) [],
        AUVIOL OFFSET(3) NUMBITS(1) [],
        INVTRAN OFFSET(4) NUMBITS(1) [],
        LSPERR OFFSET(5) NUMBITS(1) [],
        SFARVALID OFFSET(6) NUMBITS(1) [],
        LSERR OFFSET(7) NUMBITS(1) []
    ],

    /// Secure Fault Address Register description
    SFAR [
        ADDRESS OFFSET(0) NUMBITS(32) []
    ]
];

/// Possible attribute of a SAU region.
#[derive(Debug)]
pub enum SauRegionAttribute {
    /// SAU region is Secure
    Secure,
    /// SAU region is Non-Secure Callable
    NonSecureCallable,
    /// SAU region is Non-Secure
    NonSecure,
}

/// Description of a SAU region.
#[derive(Debug)]
pub struct SauRegion {
    /// First address of the region, its 5 least significant bits must be set to zero.
    pub base_address: u32,
    /// Last address of the region, its 5 least significant bits must be set to one.
    pub limit_address: u32,
    /// Attribute of the region.
    pub attribute: SauRegionAttribute,
}

/// Possible error values returned by the SAU methods.
#[derive(Debug)]
pub enum SauError {
    /// The region number parameter to set or get a region must be between 0 and
    /// region_numbers() - 1.
    RegionNumberTooBig,
    /// Bits 0 to 4 of the base address of a SAU region must be set to zero.
    WrongBaseAddress,
    /// Bits 0 to 4 of the limit address of a SAU region must be set to one.
    WrongLimitAddress,
}

pub struct SAU {
    registers: *const SauRegisters,
}

/// Create a new SAU interface for the Cortex-M33 SAU peripheral.
pub const fn new() -> SAU {
    SAU {
        registers: 0xE000EDD0 as *const SauRegisters,
    }
}

impl SAU {
    fn registers(&self) -> &SauRegisters {
        unsafe { &*self.registers }
    }

    /// Get the number of implemented SAU regions.
    pub fn region_numbers(&self) -> u8 {
        self.registers().type_reg.read(TYPE::SREGION) as u8
    }

    /// Enable the SAU.
    pub fn enable(&mut self) {
        self.registers().ctrl.modify(CTRL::ENABLE::SET);
    }

    /// Set a SAU region to a region number.
    /// SAU regions must be 32 bytes aligned and their sizes must be a multiple of 32 bytes. It
    /// means that the 5 least significant bits of the base address of a SAU region must be set to
    /// zero and the 5 least significant bits of the limit address must be set to one.
    /// The region number must be valid.
    /// This function should be executed under a critical section to prevent having inconsistent results.
    pub fn set_region(&mut self, region_number: u8, region: SauRegion) -> Result<(), SauError> {
        let base_address = region.base_address;
        let limit_address = region.limit_address;
        let attribute = region.attribute;

        if region_number >= self.region_numbers() {
            return Err(SauError::RegionNumberTooBig);
        }
        if base_address & 0x1F != 0 {
            return Err(SauError::WrongBaseAddress);
        }
        if limit_address & 0x1F != 0x1F {
            return Err(SauError::WrongLimitAddress);
        }

        self.registers()
            .rnr
            .write(RNR::REGION.val(region_number.into()));
        self.registers()
            .rbar
            .write(RBAR::BADDR.val(base_address >> 5));

        let rlar = RLAR::LADDR.val(limit_address >> 5)
            + match attribute {
                SauRegionAttribute::Secure => RLAR::NSC::CLEAR + RLAR::ENABLE::CLEAR,
                SauRegionAttribute::NonSecureCallable => RLAR::NSC::SET + RLAR::ENABLE::SET,
                SauRegionAttribute::NonSecure => RLAR::NSC::CLEAR + RLAR::ENABLE::SET,
            };
        self.registers().rlar.write(rlar);
        Ok(())
    }

    /// Get a region from the SAU.
    /// The region number must be valid.
    /// This function should be executed under a critical section to prevent having inconsistent results.
    pub fn get_region(&mut self, region_number: u8) -> Result<SauRegion, SauError> {
        if region_number >= self.region_numbers() {
            return Err(SauError::RegionNumberTooBig);
        }
        self.registers()
            .rnr
            .write(RNR::REGION.val(region_number.into()));

        let attribute = match (
            self.registers().rlar.is_set(RLAR::ENABLE),
            self.registers().rlar.is_set(RLAR::NSC),
        ) {
            (false, _) => SauRegionAttribute::Secure,
            (true, false) => SauRegionAttribute::NonSecure,
            (true, true) => SauRegionAttribute::NonSecureCallable,
        };

        Ok(SauRegion {
            base_address: self.registers().rbar.read(RBAR::BADDR) << 5,
            limit_address: (self.registers().rlar.read(RLAR::LADDR) << 5) | 0x1F,
            attribute,
        })
    }
}
