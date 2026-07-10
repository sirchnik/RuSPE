// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::registers::{ReadOnly, ReadWrite};
use tock_registers::{register_bitfields, register_structs};

register_bitfields![u32,
    pub Ctrl [
        sec_resp OFFSET(4) NUMBITS(1) [],
        autoincrement OFFSET(8) NUMBITS(1) [],
        security_lockdown OFFSET(31) NUMBITS(1) []
    ],
    pub BlkCfg [
        block_size OFFSET(0) NUMBITS(4) [],
        init_in_progress OFFSET(31) NUMBITS(1) []
    ]
];

register_structs! {
    pub RegisterBlock {
        (0x000 => pub ctrl: ReadWrite<u32, Ctrl::Register>),
        (0x004 => _reserved1),
        (0x010 => pub blk_max: ReadOnly<u32>),
        (0x014 => pub blk_cfg: ReadOnly<u32, BlkCfg::Register>),
        (0x018 => pub blk_idx: ReadWrite<u32>),
        (0x01C => pub blk_lut: ReadWrite<u32>),
        (0x020 => @END),
    }
}

pub struct Mpc {
    pub mpc_address: u32,
    pub memory_base_address: u32,
    pub memory_limit_address: u32,
    pub block_size: u32,
}

impl Mpc {
    pub fn new(mpc_address: u32, memory_base_address: u32) -> Self {
        let block_index_max = unsafe { (*Mpc::ptr(mpc_address)).blk_max.get() };
        let block_size =
            unsafe { 1 << ((*Mpc::ptr(mpc_address)).blk_cfg.read(BlkCfg::block_size) + 5) };
        unsafe {
            (*Mpc::ptr(mpc_address))
                .ctrl
                .modify(Ctrl::autoincrement::CLEAR + Ctrl::sec_resp::SET);
        }
        let memory_limit_address =
            memory_base_address + block_size * (block_index_max + 1) * 32 - 1;
        Mpc {
            mpc_address,
            memory_base_address,
            memory_limit_address,
            block_size,
        }
    }

    fn ptr(mpc_address: u32) -> *const RegisterBlock {
        mpc_address as *const _
    }

    pub fn set_non_secure(&mut self, base_address: u32, limit_address: u32) {
        // The address range needs to be inside the supported address range.
        if base_address < self.memory_base_address
            || base_address > self.memory_limit_address
            || limit_address > self.memory_limit_address
            || base_address >= limit_address
        {
            panic!("Invalid address range.");
        }
        // Base address should be at the beginning of a block.
        if !base_address.is_multiple_of(self.block_size) {
            panic!(
                "Base address not at the beginning of a block: base_address={:#X}, block_size={:#X}",
                base_address, self.block_size
            );
        }
        // Limit address should be
        if !(limit_address + 1).is_multiple_of(self.block_size) {
            panic!(
                "Limit address not at the end of a block: limit_address={:#X}, block_size={:#X}",
                limit_address, self.block_size
            );
        }
        let start_block = (base_address - self.memory_base_address) / self.block_size;
        let end_block = (limit_address + 1 - self.memory_base_address) / self.block_size;
        let mut current_idx = start_block / 32;

        unsafe {
            let regs = &*Mpc::ptr(self.mpc_address);
            regs.blk_idx.set(current_idx);
            let mut current_lut = regs.blk_lut.get();
            for block in start_block..end_block {
                let idx = block / 32;
                if idx != current_idx {
                    regs.blk_idx.set(current_idx);
                    regs.blk_lut.set(current_lut);
                    current_idx = idx;
                    regs.blk_idx.set(current_idx);
                    current_lut = regs.blk_lut.get();
                }
                current_lut |= 1 << (block % 32);
            }
            regs.blk_idx.set(current_idx);
            regs.blk_lut.set(current_lut);
        }
    }
}
