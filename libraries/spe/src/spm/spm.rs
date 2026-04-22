use core::mem::MaybeUninit;

use tock_cells::optional_cell::OptionalCell;

use crate::psa::psa_call::PsaMsg;

const MAX_CONNECTIONS: usize = 4;
const PSA_MAX_IOVEC: usize = 4;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Connection {
    pub msg: PsaMsg,
    pub invec_base: [*const u8; PSA_MAX_IOVEC],
    pub invec_accessed: [usize; PSA_MAX_IOVEC],
    pub outvec_base: [*mut u8; PSA_MAX_IOVEC],
    pub outvec_written: [usize; PSA_MAX_IOVEC],
}

pub struct Spm {
    connections: [MaybeUninit<Connection>; MAX_CONNECTIONS],
}

impl Spm {
    pub const fn new() -> Self {
        Self {
            connections: [MaybeUninit::uninit(); MAX_CONNECTIONS],
        }
    }
}
