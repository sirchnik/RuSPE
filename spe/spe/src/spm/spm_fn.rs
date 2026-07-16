// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use super::spm::{Connection, ConnectionArray, SpmCall, SpmError};
use crate::libs::mutex::Mutex;
use crate::spm_api::{CallerAttributes, PsaMsg};
use psa_interface::types::ServiceHandle;

pub trait SfnPlatform: Sync {
    fn call(&self, msg: PsaMsg) -> Result<(), crate::StatusCode>;
    fn has_permission_on_memory(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool;

    fn version(&self, handle: ServiceHandle) -> Option<u32>;
}

pub struct SpmFn<P: SfnPlatform + 'static> {
    connections: Mutex<ConnectionArray>,
    platform: &'static P,
}

// call_unprivileged is provided by the spm module to keep the policy in one
// place.

impl<P: SfnPlatform + 'static> SpmFn<P> {
    pub const fn new(platform: &'static P) -> Self {
        Self {
            connections: Mutex::new(ConnectionArray::new()),
            platform,
        }
    }

    fn add_connection(&self, connection: Connection) -> Result<(), SpmError> {
        self.connections
            .try_lock(|connections| connections.add_connection(connection))
            .map_or(Err(SpmError::MutexBusy), |result| result)
    }

    /// # Panics
    ///
    /// Panics on invalid state.
    pub fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        let msg = connection.msg;
        assert!(
            self.add_connection(connection).is_ok(),
            "SPM connection stack exhausted"
        );
        let result = self.platform.call(msg);
        self.connections
            .try_lock(super::spm::ConnectionArray::pop_connection)
            .unwrap();
        result
    }

    // Can be called by multiple threads. Multiple threads need access to different
    // connections.
    fn with_active_connection<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> R,
    ) -> Result<R, SpmError> {
        let (index, mut connection) = match self
            .connections
            .try_lock(super::spm::ConnectionArray::take_active_connection)
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

impl<P: SfnPlatform + 'static> SpmCall for SpmFn<P> {
    /// Forwards the call to the platform's call method, while managing the
    /// connection stack.
    fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        Self::call(self, connection)
    }

    fn with_active_connection<F: FnMut(&mut Connection)>(&self, mut f: F) -> Result<(), SpmError> {
        self.with_active_connection(|conn| f(conn))
    }

    /// Checks if the platform's memory permissions allow access to the
    /// specified range.
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

    fn version(&self, handle: ServiceHandle) -> Option<u32> {
        self.platform.version(handle)
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use psa_interface::types::ServiceHandle;

    use super::*;

    struct MockPlatform;
    impl SfnPlatform for MockPlatform {
        fn call(&self, _msg: PsaMsg) -> Result<(), crate::StatusCode> {
            Ok(())
        }

        fn has_permission_on_memory(
            &self,
            _base: *const u8,
            _len: usize,
            _is_write: bool,
            _caller: CallerAttributes,
        ) -> bool {
            true
        }

        fn version(&self, _handle: ServiceHandle) -> Option<u32> {
            Some(1)
        }
    }

    static MOCK_PLATFORM: MockPlatform = MockPlatform;

    fn create_dummy_connection_with_handle(handle: ServiceHandle) -> Connection {
        use crate::spm::spm::PSA_MAX_IOVEC;
        Connection {
            msg: PsaMsg::new(handle, 1, CallerAttributes::SECURE_UNPRIVILEGED),
            invec_base: [ptr::null(); PSA_MAX_IOVEC],
            invec_accessed: [0; PSA_MAX_IOVEC],
            invec_mapped: [false; PSA_MAX_IOVEC],
            invec_unmapped: [false; PSA_MAX_IOVEC],
            outvec_base: [ptr::null_mut(); PSA_MAX_IOVEC],
            outvec_written: [0; PSA_MAX_IOVEC],
            outvec_mapped: [false; PSA_MAX_IOVEC],
            outvec_unmapped: [false; PSA_MAX_IOVEC],
        }
    }

    fn create_dummy_connection() -> Connection {
        create_dummy_connection_with_handle(ServiceHandle::Crypto)
    }

    #[test]
    fn test_spm_fn_call_success() {
        let spm = SpmFn::new(&MOCK_PLATFORM);
        let conn = create_dummy_connection();
        let res = spm.call(conn);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn test_spm_fn_has_permission() {
        let spm = SpmFn::new(&MOCK_PLATFORM);
        let perm = spm.has_real_permission(
            ptr::null(),
            10,
            false,
            CallerAttributes::SECURE_UNPRIVILEGED,
        );
        assert!(perm);
    }

    #[test]
    fn test_spm_fn_version() {
        let spm = SpmFn::new(&MOCK_PLATFORM);
        assert_eq!(spm.version(ServiceHandle::Crypto), Some(1));
    }

    #[test]
    fn test_with_active_connection() {
        let spm = SpmFn::new(&MOCK_PLATFORM);
        let conn = create_dummy_connection();
        let _ = spm.add_connection(conn);

        let res = spm.with_active_connection(|c| c.msg.handle == ServiceHandle::Crypto);
        assert_eq!(res, Ok(true));

        // clean up
        spm.connections
            .try_lock(|connections| connections.pop_connection())
            .unwrap();
    }

    #[test]
    fn test_multiple_psa_calls_nested() {
        let spm = SpmFn::new(&MOCK_PLATFORM);

        let conn1 = create_dummy_connection_with_handle(ServiceHandle::Crypto);
        let conn2 = create_dummy_connection_with_handle(ServiceHandle::AttestationService);
        let conn3 =
            create_dummy_connection_with_handle(ServiceHandle::InternalTrustedStorageService);

        // Simulate nested PSA calls
        assert_eq!(spm.add_connection(conn1), Ok(()));
        assert_eq!(spm.add_connection(conn2), Ok(()));
        assert_eq!(spm.add_connection(conn3), Ok(()));

        // Top should be conn3
        spm.with_active_connection(|c| {
            assert_eq!(c.msg.handle, ServiceHandle::InternalTrustedStorageService);
        })
        .unwrap();
        spm.connections.try_lock(|c| c.pop_connection()).unwrap();

        // Top should be conn2
        spm.with_active_connection(|c| {
            assert_eq!(c.msg.handle, ServiceHandle::AttestationService);
        })
        .unwrap();
        spm.connections.try_lock(|c| c.pop_connection()).unwrap();

        // Top should be conn1
        spm.with_active_connection(|c| {
            assert_eq!(c.msg.handle, ServiceHandle::Crypto);
        })
        .unwrap();
        spm.connections.try_lock(|c| c.pop_connection()).unwrap();
    }

    #[test]
    fn test_multiple_psa_calls_sequential() {
        let spm = SpmFn::new(&MOCK_PLATFORM);
        for _ in 0..10 {
            let conn = create_dummy_connection();
            assert_eq!(spm.call(conn), Ok(()));
        }
    }
}
