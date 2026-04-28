// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

//! PSA standard error codes used by the PSA interface.

use crate::types::PsaStatus;

/// PSA-aligned status code returned by PSA APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(isize)]
pub enum StatusCode {
    /// `_Success` is encoded as `Ok()` but for FFI it is the integer `0`.
    _Success = 0,
    /// Abnormal/abusive call from the client.
    ProgrammerError = -129,
    /// Caller is not permitted to connect.
    ConnectionRefused = -130,
    /// Caller cannot connect right now.
    ConnectionBusy = -131,
    /// Undefined failure cause.
    GenericError = -132,
    /// Action denied by policy.
    NotPermitted = -133,
    /// Operation/parameter unsupported.
    NotSupported = -134,
    /// Invalid parameter or combination.
    InvalidArgument = -135,
    /// Key/handle identifier is not valid.
    InvalidHandle = -136,
    /// Action cannot be performed in current state.
    BadState = -137,
    /// Output buffer is too small.
    BufferTooSmall = -138,
    /// Item already exists.
    AlreadyExists = -139,
    /// Requested item does not exist.
    DoesNotExist = -140,
    /// Not enough runtime memory.
    InsufficientMemory = -141,
    /// Not enough persistent storage.
    InsufficientStorage = -142,
    /// Insufficient data when reading.
    InsufficientData = -143,
    /// Service can no longer operate correctly.
    ServiceFailure = -144,
    /// Communication failure inside the implementation.
    CommunicationFailure = -145,
    /// Storage failure that may have led to data loss.
    StorageFailure = -146,
    /// Hardware failure detected.
    HardwareFailure = -147,
    /// Signature/MAC/hash is incorrect.
    InvalidSignature = -149,
    /// A tampering attempt was detected.
    CorruptionDetected = -151,
    /// Stored data has been corrupted.
    DataCorrupt = -152,
    /// Stored data is not valid for the implementation.
    DataInvalid = -153,
    /// Interruptible operation still has work to do; call again with the same context.
    OperationIncomplete = -248,
}

impl From<StatusCode> for PsaStatus {
    fn from(err: StatusCode) -> PsaStatus {
        err as PsaStatus
    }
}

/// Convert a PSA result to a [`PsaStatus`] integer for FFI/veneer return.
///
/// `Ok(())` becomes `_Success` (0); errors become their PSA-defined
/// negative integer.
pub fn into_psa_status(r: Result<(), StatusCode>) -> isize {
    match r {
        Ok(()) => StatusCode::_Success as isize,
        Err(e) => e as isize,
    }
}
