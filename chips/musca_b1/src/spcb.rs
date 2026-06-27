// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use tock_registers::{
    interfaces::ReadWriteable, register_bitfields, register_structs, registers::ReadWrite,
};

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

pub fn enable_idau_nsc_code() {
    unsafe {
        let spcb = &*(0x50080000u32 as *const SpcbRegisters);
        spcb.nsc_cfg.modify(NscCfg::allow_sau_code_nsc::SET);
    }
}

pub fn enable_uart1_ns() {
    unsafe {
        let spcb = &*(0x50080000u32 as *const SpcbRegisters);
        // WORKAROUND:
        // In datasheet Bit 5 controls UART0 security (1 = Non-Secure)
        // In reality it control UART1 somehow or just plain doesn't work idk.
        spcb.apb_ns_ppc_exp1.modify(ApbNsPpcExp1::uart1_ns::SET);
    }
}
