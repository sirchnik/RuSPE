use crate::{libs::mutex::Mutex, psa::psa_call::PsaMsg};

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

// #Safety
// Connection is not Send because it contains raw pointers.
// Rust did declare raw pointers as !Send as it cannot guarantee ownership and lifetimes.
// As raw pointers can only be dereferenced in unsafe code, we circumvent the language design and
// mark Connection Send.
unsafe impl Send for Connection {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpmError {
    MutexBusy,
    ConnectionStackFull,
    NoActiveConnection,
    CorruptedConnectionStack,
}

struct ConnectionArray {
    connections: [Option<Connection>; MAX_CONNECTIONS],
    top_connection: usize,
}

impl ConnectionArray {
    pub const fn new() -> Self {
        Self {
            connections: [None; MAX_CONNECTIONS],
            top_connection: 0,
        }
    }

    fn add_connection(&mut self, connection: Connection) -> Result<(), SpmError> {
        if self.top_connection >= MAX_CONNECTIONS {
            return Err(SpmError::ConnectionStackFull);
        }

        self.connections[self.top_connection] = Some(connection);
        self.top_connection += 1;

        Ok(())
    }

    fn take_active_connection(&mut self) -> Result<(usize, Connection), SpmError> {
        if self.top_connection == 0 {
            return Err(SpmError::NoActiveConnection);
        }

        let index = self.top_connection - 1;
        let connection = self.connections[index]
            .take()
            .ok_or(SpmError::CorruptedConnectionStack)?;

        Ok((index, connection))
    }

    fn restore_active_connection(
        &mut self,
        index: usize,
        connection: Connection,
    ) -> Result<(), SpmError> {
        if index >= MAX_CONNECTIONS || self.connections[index].is_some() {
            return Err(SpmError::CorruptedConnectionStack);
        }

        self.connections[index] = Some(connection);

        Ok(())
    }
}

pub trait SpmPlatform: Sync {
    fn call(&self, msg: PsaMsg) -> Result<(), crate::StatusCode>;
}

/// Object-safe trait for SPM operations, used for type-erased storage in statics.
pub trait SpmCall: Sync {
    fn call(&self, connection: Connection) -> Result<(), crate::StatusCode>;
    fn with_active_connection(&self, f: &mut dyn FnMut(&mut Connection)) -> Result<(), SpmError>;
}

pub struct Spm<P: SpmPlatform + 'static> {
    connections: Mutex<ConnectionArray>,
    platform: &'static P,
}

impl<P: SpmPlatform + 'static> Spm<P> {
    pub const fn new(platform: &'static P) -> Self {
        Self {
            connections: Mutex::new(ConnectionArray::new()),
            platform,
        }
    }

    fn add_connection(&self, connection: Connection) -> Result<(), SpmError> {
        let result = match self
            .connections
            .try_lock(|connections| connections.add_connection(connection))
        {
            Ok(result) => result,
            Err(_) => Err(SpmError::MutexBusy),
        };
        result
    }

    pub fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        if self.add_connection(connection).is_err() {
            panic!("SPM connection stack exhausted");
        }
        self.platform.call(connection.msg)
    }

    // Can be called by multiple threads. Multiple threads need access to different connections.
    fn with_active_connection<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> R,
    ) -> Result<R, SpmError> {
        let (index, mut connection) = match self
            .connections
            .try_lock(|connections| connections.take_active_connection())
        {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(SpmError::MutexBusy),
        };

        let result = f(&mut connection);

        match self
            .connections
            .try_lock(|connections| connections.restore_active_connection(index, connection))
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(SpmError::MutexBusy),
        }
        Ok(result)
    }
}

impl<P: SpmPlatform + 'static> SpmCall for Spm<P> {
    fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        Spm::call(self, connection)
    }

    fn with_active_connection(&self, f: &mut dyn FnMut(&mut Connection)) -> Result<(), SpmError> {
        self.with_active_connection(|conn| f(conn))
    }
}
