// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

//! EFUSE interface

use helpers::static_ref::StaticRef;
use tock_registers::interfaces::Readable;
use tock_registers::registers::{ReadOnly, ReadWrite};
use tock_registers::{register_bitfields, register_structs};

register_structs! {
    /// EFUSE MXS40 registers
    EfuseRegisters {
        /// Control
        (0x000 => ctl: ReadWrite<u32, CTL::Register>),
        (0x004 => _reserved0),
        /// Test
        (0x100 => test: ReadWrite<u32, TEST::Register>),
        (0x104 => _reserved1),
        /// Command
        (0x110 => cmd: ReadWrite<u32, CMD::Register>),
        /// Config
        (0x114 => config: ReadWrite<u32, CONFIG::Register>),
        (0x118 => _reserved2),
        /// Sequencer default value
        (0x120 => seq_default: ReadWrite<u32, SEQ_DEFAULT::Register>),
        (0x124 => _reserved3),
        /// Sequencer read control
        (0x140 => seq_read_ctl: [ReadWrite<u32, SEQ_READ_CTL::Register>; 8]),
        /// Sequencer program control
        (0x160 => seq_program_ctl: [ReadWrite<u32, SEQ_PROGRAM_CTL::Register>; 8]),
        /// Content of Boot Row latches at power-on-reset
        (0x180 => bootrow: ReadOnly<u32, BOOTROW::Register>),
        (0x184 => @END),
    }
}

register_bitfields![u32,
    CTL [
        /// CC312 lock - when set locks 8 bytes beyond the end of the PROT_MASTER defined space for read access.
        LOCK_CC312_REGION OFFSET(0) NUMBITS(1) [],
        /// IP enable.
        ENABLED OFFSET(31) NUMBITS(1) []
    ],
    TEST [
        /// Margin read control.
        MARG_READ OFFSET(0) NUMBITS(2) []
    ],
    CMD [
        /// Bit data to program.
        BIT_DATA OFFSET(0) NUMBITS(1) [],
        /// Bit address within a byte.
        BIT_ADDR OFFSET(4) NUMBITS(3) [],
        /// Byte address within an eFUSE macro.
        BYTE_ADDR OFFSET(8) NUMBITS(5) [],
        /// Macro address.
        MACRO_ADDR OFFSET(16) NUMBITS(4) [],
        /// Start program operation.
        START OFFSET(31) NUMBITS(1) []
    ],
    CONFIG [
        /// Enable 32B programming.
        PGM_32B_EN OFFSET(0) NUMBITS(1) []
    ],
    SEQ_DEFAULT [
        STROBE_A OFFSET(16) NUMBITS(1) [],
        STROBE_B OFFSET(17) NUMBITS(1) [],
        STROBE_C OFFSET(18) NUMBITS(1) [],
        STROBE_D OFFSET(19) NUMBITS(1) [],
        STROBE_E OFFSET(20) NUMBITS(1) [],
        STROBE_F OFFSET(21) NUMBITS(1) [],
        STROBE_G OFFSET(22) NUMBITS(1) []
    ],
    SEQ_READ_CTL [
        /// Number of IP clock cycles minus 1.
        CYCLES OFFSET(0) NUMBITS(10) [],
        STROBE_A OFFSET(16) NUMBITS(1) [],
        STROBE_B OFFSET(17) NUMBITS(1) [],
        STROBE_C OFFSET(18) NUMBITS(1) [],
        STROBE_D OFFSET(19) NUMBITS(1) [],
        STROBE_E OFFSET(20) NUMBITS(1) [],
        STROBE_F OFFSET(21) NUMBITS(1) [],
        STROBE_G OFFSET(22) NUMBITS(1) [],
        DONE OFFSET(31) NUMBITS(1) []
    ],
    SEQ_PROGRAM_CTL [
        /// Number of IP clock cycles minus 1.
        CYCLES OFFSET(0) NUMBITS(10) [],
        STROBE_A OFFSET(16) NUMBITS(1) [],
        STROBE_B OFFSET(17) NUMBITS(1) [],
        STROBE_C OFFSET(18) NUMBITS(1) [],
        STROBE_D OFFSET(19) NUMBITS(1) [],
        STROBE_E OFFSET(20) NUMBITS(1) [],
        STROBE_F OFFSET(21) NUMBITS(1) [],
        STROBE_G OFFSET(22) NUMBITS(1) [],
        DONE OFFSET(31) NUMBITS(1) []
    ],
    BOOTROW [
        BOOT_ROW_DATA OFFSET(0) NUMBITS(32) [
        Virgin = 0x0000,
        Sort = 0x0029,
        Provisioned = 0x00E9,
        NormalProvisioned = 0xC0E9,
        Normal = 0xC029,
        Secure = 0xC3E9,
        NormalNoSecure = 0xCC29,
        Rma = 0xF3E9,
        Corrupted = 0xFFFF,
        ]
    ]
];

const EFUSE_BASE: StaticRef<EfuseRegisters> =
    unsafe { StaticRef::new(0x42610000 as *const EfuseRegisters) };

pub type SyslibLcsMode = BOOTROW::BOOT_ROW_DATA::Value;

pub fn get_device_lifecycle() -> SyslibLcsMode {
    EFUSE_BASE
        .bootrow
        .read_as_enum(BOOTROW::BOOT_ROW_DATA)
        .unwrap_or(SyslibLcsMode::Corrupted)
}
