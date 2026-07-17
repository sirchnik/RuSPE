// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

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
    /// Interruptible operation still has work to do; call again with the same
    /// context.
    OperationIncomplete = -248,
}

impl From<StatusCode> for PsaStatus {
    fn from(status: StatusCode) -> Self {
        status as Self
    }
}

impl TryFrom<usize> for StatusCode {
    type Error = PsaStatus;

    fn try_from(status: usize) -> Result<Self, Self::Error> {
        Self::try_from(status.cast_signed())
    }
}

impl TryFrom<PsaStatus> for StatusCode {
    type Error = PsaStatus;

    fn try_from(status: PsaStatus) -> Result<Self, Self::Error> {
        match status {
            0 => Ok(Self::_Success),
            -129 => Ok(Self::ProgrammerError),
            -130 => Ok(Self::ConnectionRefused),
            -131 => Ok(Self::ConnectionBusy),
            -132 => Ok(Self::GenericError),
            -133 => Ok(Self::NotPermitted),
            -134 => Ok(Self::NotSupported),
            -135 => Ok(Self::InvalidArgument),
            -136 => Ok(Self::InvalidHandle),
            -137 => Ok(Self::BadState),
            -138 => Ok(Self::BufferTooSmall),
            -139 => Ok(Self::AlreadyExists),
            -140 => Ok(Self::DoesNotExist),
            -141 => Ok(Self::InsufficientMemory),
            -142 => Ok(Self::InsufficientStorage),
            -143 => Ok(Self::InsufficientData),
            -144 => Ok(Self::ServiceFailure),
            -145 => Ok(Self::CommunicationFailure),
            -146 => Ok(Self::StorageFailure),
            -147 => Ok(Self::HardwareFailure),
            -149 => Ok(Self::InvalidSignature),
            -151 => Ok(Self::CorruptionDetected),
            -152 => Ok(Self::DataCorrupt),
            -153 => Ok(Self::DataInvalid),
            -248 => Ok(Self::OperationIncomplete),
            _ => Err(status),
        }
    }
}

/// Convert a PSA result to a [`PsaStatus`] integer for FFI/veneer return.
///
/// `Ok(())` becomes `_Success` (0); errors become their PSA-defined
/// negative integer.
#[must_use]
pub const fn into_psa_status(r: Result<(), StatusCode>) -> isize {
    match r {
        Ok(()) => StatusCode::_Success as isize,
        Err(e) => e as isize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_to_psa_status_success() {
        let psa: PsaStatus = StatusCode::_Success.into();
        assert_eq!(psa, 0);
    }

    #[test]
    fn status_code_to_psa_status_all_variants() {
        let cases: &[(StatusCode, isize)] = &[
            (StatusCode::_Success, 0),
            (StatusCode::ProgrammerError, -129),
            (StatusCode::ConnectionRefused, -130),
            (StatusCode::ConnectionBusy, -131),
            (StatusCode::GenericError, -132),
            (StatusCode::NotPermitted, -133),
            (StatusCode::NotSupported, -134),
            (StatusCode::InvalidArgument, -135),
            (StatusCode::InvalidHandle, -136),
            (StatusCode::BadState, -137),
            (StatusCode::BufferTooSmall, -138),
            (StatusCode::AlreadyExists, -139),
            (StatusCode::DoesNotExist, -140),
            (StatusCode::InsufficientMemory, -141),
            (StatusCode::InsufficientStorage, -142),
            (StatusCode::InsufficientData, -143),
            (StatusCode::ServiceFailure, -144),
            (StatusCode::CommunicationFailure, -145),
            (StatusCode::StorageFailure, -146),
            (StatusCode::HardwareFailure, -147),
            (StatusCode::InvalidSignature, -149),
            (StatusCode::CorruptionDetected, -151),
            (StatusCode::DataCorrupt, -152),
            (StatusCode::DataInvalid, -153),
            (StatusCode::OperationIncomplete, -248),
        ];

        for &(code, expected) in cases {
            let psa: PsaStatus = code.into();
            assert_eq!(
                psa, expected,
                "StatusCode::{code:?} should map to {expected}"
            );
        }
    }

    #[test]
    fn psa_status_to_status_code_roundtrip() {
        let codes = [
            StatusCode::_Success,
            StatusCode::ProgrammerError,
            StatusCode::ConnectionRefused,
            StatusCode::ConnectionBusy,
            StatusCode::GenericError,
            StatusCode::NotPermitted,
            StatusCode::NotSupported,
            StatusCode::InvalidArgument,
            StatusCode::InvalidHandle,
            StatusCode::BadState,
            StatusCode::BufferTooSmall,
            StatusCode::AlreadyExists,
            StatusCode::DoesNotExist,
            StatusCode::InsufficientMemory,
            StatusCode::InsufficientStorage,
            StatusCode::InsufficientData,
            StatusCode::ServiceFailure,
            StatusCode::CommunicationFailure,
            StatusCode::StorageFailure,
            StatusCode::HardwareFailure,
            StatusCode::InvalidSignature,
            StatusCode::CorruptionDetected,
            StatusCode::DataCorrupt,
            StatusCode::DataInvalid,
            StatusCode::OperationIncomplete,
        ];

        for code in codes {
            let psa: PsaStatus = code.into();
            let back = StatusCode::try_from(psa).expect("round-trip should succeed");
            assert_eq!(back, code);
        }
    }

    #[test]
    fn psa_status_try_from_unknown_returns_err() {
        assert_eq!(StatusCode::try_from(1_isize), Err(1));
        assert_eq!(StatusCode::try_from(-999_isize), Err(-999));
        assert_eq!(StatusCode::try_from(-148_isize), Err(-148)); // gap between -147 and -149
        assert_eq!(StatusCode::try_from(-150_isize), Err(-150)); // gap between -149 and -151
    }

    #[test]
    fn into_psa_status_ok_returns_zero() {
        assert_eq!(into_psa_status(Ok(())), 0);
    }

    #[test]
    fn into_psa_status_err_returns_negative() {
        assert_eq!(into_psa_status(Err(StatusCode::GenericError)), -132);
        assert_eq!(into_psa_status(Err(StatusCode::InvalidArgument)), -135);
        assert_eq!(into_psa_status(Err(StatusCode::OperationIncomplete)), -248);
    }
}
