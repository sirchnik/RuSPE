// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use super::spm::{Connection, ConnectionArray, SpmCall, SpmError};
use crate::{
    libs::mutex::Mutex,
    spm_api::{CallerAttributes, PsaMsg},
};

pub trait SfnPlatform: Sync {
    fn call(&self, msg: PsaMsg) -> Result<(), crate::StatusCode>;
    fn has_permission_on_memory(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool;

    fn version(&self, handle: psa_interface::types::ServiceHandle) -> Option<u32>;
}

pub struct SpmFn<P: SfnPlatform + 'static> {
    connections: Mutex<ConnectionArray>,
    platform: &'static P,
}

// call_unprivileged is provided by the spm module to keep the policy in one place.

impl<P: SfnPlatform + 'static> SpmFn<P> {
    pub const fn new(platform: &'static P) -> Self {
        Self {
            connections: Mutex::new(ConnectionArray::new()),
            platform,
        }
    }

    fn add_connection(&self, connection: Connection) -> Result<(), SpmError> {
        match self
            .connections
            .try_lock(|connections| connections.add_connection(connection))
        {
            Ok(result) => result,
            Err(()) => Err(SpmError::MutexBusy),
        }
    }

    pub fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        let msg = connection.msg;
        if self.add_connection(connection).is_err() {
            panic!("SPM connection stack exhausted");
        }
        let result = self.platform.call(msg);
        self.connections
            .try_lock(|connections| connections.pop_connection())
            .unwrap();
        result
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
            Err(()) => return Err(SpmError::MutexBusy),
        };

        let result = f(&mut connection);

        match self
            .connections
            .try_lock(|connections| connections.restore_active_connection(index, connection))
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(()) => return Err(SpmError::MutexBusy),
        }
        Ok(result)
    }
}

impl<P: SfnPlatform + 'static> SpmCall for SpmFn<P> {
    /// Forwards the call to the platform's call method, while managing the connection stack.
    fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        SpmFn::call(self, connection)
    }

    fn with_active_connection<F: FnMut(&mut Connection)>(&self, mut f: F) -> Result<(), SpmError> {
        self.with_active_connection(|conn| f(conn))
    }

    /// Checks if the platform's memory permissions allow access to the specified range.
    fn has_real_permission(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool {
        self.platform
            .has_permission_on_memory(base, len, is_write, caller)
    }

    fn map_vec(&self, _is_outvec: bool, _vec_idx: u32, _base: *const u8, _size: usize) {}
    fn unmap_vec(&self, _is_outvec: bool, _vec_idx: u32) {}

    fn version(&self, handle: psa_interface::types::ServiceHandle) -> Option<u32> {
        self.platform.version(handle)
    }
}
