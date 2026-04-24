use core::cell::Cell;

use crate::psa::psa_call::PsaMsg;

const MAX_CONNECTIONS: usize = 4;
const PSA_MAX_IOVEC: usize = 4;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Connection {
    pub msg: PsaMsg,
    pub invec_base: [*const u8; PSA_MAX_IOVEC],
    pub invec_accessed: [usize; PSA_MAX_IOVEC],
    pub outvec_base: [*mut u8; PSA_MAX_IOVEC],
    pub outvec_written: [usize; PSA_MAX_IOVEC],
}

pub trait SpmPlatform {
    fn call(&self, msg: PsaMsg);
}

use core::fmt::Debug;
impl Debug for dyn SpmPlatform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SpmPlatform")
    }
}

#[derive(Clone, Debug)]
pub struct Spm {
    connections: [Cell<Option<Connection>>; MAX_CONNECTIONS],
    top_connection: Cell<usize>,
    platform: &'static dyn SpmPlatform,
}

impl Spm {
    pub const fn new(platform: &'static dyn SpmPlatform) -> Self {
        Self {
            connections: [
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
            ],
            top_connection: Cell::new(0),
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

    pub fn call(&self, connection: Connection) {
        self.add_connection(connection);
        self.platform.call(connection.msg)
    }
}
