// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::spm_api::{CallerAttributes, PsaMsg};

use psa_interface::types::ServiceHandle;

const MAX_CONNECTIONS: usize = 4;
pub const PSA_MAX_IOVEC: usize = 4;

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

// # Safety
// Connection is not Send because it contains raw pointers.
// Rust did declare raw pointers as !Send as it cannot guarantee ownership and
// lifetimes. As raw pointers can only be dereferenced in unsafe code, we
// circumvent the language design and mark Connection Send.
// There was once a discussion about this in the Rust community https://internals.rust-lang.org/t/shouldnt-pointers-be-send-sync-or/8818
unsafe impl Send for Connection {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpmError {
    MutexBusy,
    ConnectionStackFull,
    EmptyConnectionStack,
    NoActiveConnection,
    CorruptedConnectionStack,
}

pub(crate) struct ConnectionArray {
    // MaybeUninit for fixing bug in O3
    connections: [core::mem::MaybeUninit<Connection>; MAX_CONNECTIONS],
    present: [bool; MAX_CONNECTIONS],
    top_connection: usize,
}

impl ConnectionArray {
    pub const fn new() -> Self {
        Self {
            // SAFETY: An uninitialized array of MaybeUninit is valid.
            connections: unsafe { core::mem::MaybeUninit::uninit().assume_init() },
            present: [false; MAX_CONNECTIONS],
            top_connection: 0,
        }
    }

    pub(crate) const fn add_connection(&mut self, connection: Connection) -> Result<(), SpmError> {
        if self.top_connection >= MAX_CONNECTIONS {
            return Err(SpmError::ConnectionStackFull);
        }

        self.connections[self.top_connection].write(connection);
        self.present[self.top_connection] = true;
        self.top_connection += 1;

        Ok(())
    }

    pub(crate) const fn take_active_connection(&mut self) -> Result<(usize, Connection), SpmError> {
        if self.top_connection == 0 {
            return Err(SpmError::NoActiveConnection);
        }

        let index = self.top_connection - 1;
        if !self.present[index] {
            return Err(SpmError::CorruptedConnectionStack);
        }

        // SAFETY: We checked `present[index]` which guarantees it was initialized.
        let connection = unsafe { self.connections[index].assume_init_read() };
        self.present[index] = false;

        Ok((index, connection))
    }

    pub(crate) const fn restore_active_connection(
        &mut self,
        index: usize,
        connection: Connection,
    ) -> Result<(), SpmError> {
        if index >= MAX_CONNECTIONS || self.present[index] {
            return Err(SpmError::CorruptedConnectionStack);
        }

        self.connections[index].write(connection);
        self.present[index] = true;

        Ok(())
    }

    pub(crate) fn pop_connection(&mut self) {
        if self.top_connection > 0 {
            self.top_connection -= 1;
            if self.present[self.top_connection] {
                // SAFETY: We checked `present` is true, so it is initialized.
                unsafe { self.connections[self.top_connection].assume_init_drop() };
                self.present[self.top_connection] = false;
            }
        }
    }

    pub(crate) const fn peek_active_connection(&self) -> Result<&Connection, SpmError> {
        if self.top_connection == 0 {
            return Err(SpmError::EmptyConnectionStack);
        }
        let index = self.top_connection - 1;
        if self.present[index] {
            // SAFETY: We checked `present[index]` which guarantees it was initialized.
            Ok(unsafe { self.connections[index].assume_init_ref() })
        } else {
            Err(SpmError::CorruptedConnectionStack)
        }
    }
}

/// Object-safe trait for SPM operations, used for type-erased storage in
/// statics.
pub trait SpmCall: Sync {
    fn call(&self, connection: Connection) -> Result<(), crate::StatusCode>;

    fn with_active_connection<F: FnMut(&mut Connection)>(&self, f: F) -> Result<(), SpmError>;
    fn has_real_permission(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool;
    fn map_vec(&self, is_outvec: bool, vec_idx: u32, base: *const u8, size: usize);
    fn unmap_vec(&self, is_outvec: bool, vec_idx: u32);
    fn version(&self, handle: ServiceHandle) -> Option<u32>;
}
