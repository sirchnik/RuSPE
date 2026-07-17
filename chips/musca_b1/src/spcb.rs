// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use tock_registers::interfaces::ReadWriteable;
use tock_registers::registers::ReadWrite;
use tock_registers::{register_bitfields, register_structs};

register_bitfields![u32,
    pub NscCfg [
        allow_sau_code_nsc OFFSET(0) NUMBITS(1) []
    ],
    pub ApbNsPpcExp1 [
        uart1_ns OFFSET(5) NUMBITS(1) []
    ]
];

register_structs! {
    pub SpcbRegisters {
        (0x000 => _reserved0),
        (0x014 => pub nsc_cfg: ReadWrite<u32, NscCfg::Register>),
        (0x018 => _reserved1),
        (0x084 => pub apb_ns_ppc_exp1: ReadWrite<u32, ApbNsPpcExp1::Register>),
        (0x088 => @END),
    }
}

/// Enable IDAU NSC code region
///
/// # Safety
/// Modifying IDAU state changes memory execution safety boundaries.
pub unsafe fn enable_idau_nsc_code() {
    // SAFETY: Register block is valid. Modifying it is unsafe and the caller's
    // responsibility.
    unsafe {
        let spcb = &*(0x5008_0000u32 as *const SpcbRegisters);
        spcb.nsc_cfg.modify(NscCfg::allow_sau_code_nsc::SET);
    }
}

/// Enable UART1 non-secure access
///
/// # Safety
/// Changing peripheral security boundaries can break isolation.
pub unsafe fn enable_uart1_ns() {
    // SAFETY: Register block is valid. Modifying it is unsafe and the caller's
    // responsibility.
    unsafe {
        let spcb = &*(0x5008_0000u32 as *const SpcbRegisters);
        // WORKAROUND:
        // In datasheet Bit 5 controls UART0 security (1 = Non-Secure)
        // In reality it control UART1 somehow or just plain doesn't work idk.
        spcb.apb_ns_ppc_exp1.modify(ApbNsPpcExp1::uart1_ns::SET);
    }
}
