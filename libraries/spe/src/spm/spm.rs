use core::cell::Cell;

use crate::{libs::mutex::InterruptUnsafeMutex, psa::psa_call::PsaMsg};

const MAX_CONNECTIONS: usize = 4;
pub const PSA_MAX_IOVEC: usize = 4;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Connection {
    pub msg: PsaMsg,
    pub invec_base: [*const u8; PSA_MAX_IOVEC],
    pub invec_accessed: [usize; PSA_MAX_IOVEC],
    pub invec_mapped: [bool; PSA_MAX_IOVEC],
    pub invec_unmapped: [bool; PSA_MAX_IOVEC],
    pub outvec_base: [*mut u8; PSA_MAX_IOVEC],
    pub outvec_written: [usize; PSA_MAX_IOVEC],
    pub outvec_mapped: [bool; PSA_MAX_IOVEC],
    pub outvec_unmapped: [bool; PSA_MAX_IOVEC],
}

pub trait SpmPlatform: Sync {
    fn call(&self, msg: PsaMsg) -> Result<(), crate::StatusCode>;
}

use core::fmt::Debug;
impl Debug for dyn SpmPlatform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SpmPlatform")
    }
}

#[derive(Debug)]
pub struct Spm {
    connections: [InterruptUnsafeMutex<Cell<Option<Connection>>>; MAX_CONNECTIONS],
    top_connection: InterruptUnsafeMutex<Cell<usize>>,
    platform: &'static dyn SpmPlatform,
}

impl Spm {
    pub const fn new(platform: &'static dyn SpmPlatform) -> Self {
        Self {
            connections: [
                InterruptUnsafeMutex::new(Cell::new(None)),
                InterruptUnsafeMutex::new(Cell::new(None)),
                InterruptUnsafeMutex::new(Cell::new(None)),
                InterruptUnsafeMutex::new(Cell::new(None)),
            ],
            top_connection: InterruptUnsafeMutex::new(Cell::new(0)),
            platform,
        }
    }

    fn add_connection(&self, connection: Connection) -> Result<(), ()> {
        if self.top_connection.get() >= MAX_CONNECTIONS {
            return Err(());
        }

        self.connections[self.top_connection.get()].set(Some(connection));
        self.top_connection.set(self.top_connection.get() + 1);

        Ok(())
    }

    pub fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        if self.add_connection(connection).is_err() {
            panic!("SPM connection stack exhausted");
        }
        self.platform.call(connection.msg)
    }

    pub fn with_active_connection<R>(&self, f: impl FnOnce(&mut Connection) -> R) -> Option<R> {
        let index = self.top_connection.get().checked_sub(1)?;
        let mut connection = self.connections[index].take()?;
        let result = f(&mut connection);
        self.connections[index].set(Some(connection));
        Some(result)
    }
}
