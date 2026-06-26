use bitfield::bitfield;
use volatile_register::{RO, RW};
pub struct Mpc {
    pub mpc_address: u32,
    pub memory_base_address: u32,
    pub memory_limit_address: u32,
    pub block_size: u32,
}
impl Mpc {
    pub fn new(mpc_address: u32, memory_base_address: u32) -> Self {
        let block_index_max = unsafe { (*Mpc::ptr(mpc_address)).blk_max.read() };
        let block_size = unsafe { 1 << ((*Mpc::ptr(mpc_address)).blk_cfg.read().block_size() + 5) };
        unsafe {
            (*Mpc::ptr(mpc_address)).ctrl.modify(|mut ctrl| {
                ctrl.set_autoincrement(false);
                // Bus Error instead of RAZ/WI
                ctrl.set_sec_resp(true);
                ctrl
            });
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
}
#[repr(C)]
pub struct RegisterBlock {
    pub ctrl: RW<Ctrl>,
    _reserved1: [u32; 3],
    pub blk_max: RO<u32>,
    pub blk_cfg: RO<BlkCfg>,
    pub blk_idx: RW<u32>,
    pub blk_lut: RW<u32>,
    // Interrupt registers are not implemented
    _unimplemented: [u32; 6],
    _reserved2: [u32; 0xFC8],
}
bitfield! {
    /// Control Register description
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Ctrl(u32);
    get_security_lockdown, set_security_lockdown: 31;
    get_autoincrement, set_autoincrement: 8;
    get_sec_resp, set_sec_resp: 4;
}
bitfield! {
    /// Control Register description
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct BlkCfg(u32);
    init_in_progress, _: 31;
    block_size, _: 3, 0;
}
impl Mpc {
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
        if base_address % self.block_size != 0 {
            panic!(
                "Base address not at the beginning of a block: base_address={:#X}, block_size={:#X}",
                base_address, self.block_size
            );
        }
        // Limit address should be
        if (limit_address + 1) % self.block_size != 0 {
            panic!(
                "Limit address not at the end of a block: limit_address={:#X}, block_size={:#X}",
                limit_address, self.block_size
            );
        }
        let start_block = (base_address - self.memory_base_address) / self.block_size;
        let end_block = (limit_address + 1 - self.memory_base_address) / self.block_size;
        let mut current_idx = start_block / 32;

        unsafe {
            (*Mpc::ptr(self.mpc_address)).blk_idx.write(current_idx);
            let mut current_lut = (*Mpc::ptr(self.mpc_address)).blk_lut.read();
            for block in start_block..end_block {
                let idx = block / 32;
                if idx != current_idx {
                    (*Mpc::ptr(self.mpc_address)).blk_idx.write(current_idx);
                    (*Mpc::ptr(self.mpc_address)).blk_lut.write(current_lut);
                    current_idx = idx;
                    (*Mpc::ptr(self.mpc_address)).blk_idx.write(current_idx);
                    current_lut = (*Mpc::ptr(self.mpc_address)).blk_lut.read();
                }
                current_lut |= 1 << (block % 32);
            }
            (*Mpc::ptr(self.mpc_address)).blk_idx.write(current_idx);
            (*Mpc::ptr(self.mpc_address)).blk_lut.write(current_lut);
        }
    }
}
