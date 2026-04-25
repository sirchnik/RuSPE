use crate::{
    StatusCode,
    attest::cose_token::{
        compute_initial_attestation_token_size, encode_initial_attestation_token,
    },
    psa::{
        iovec::{PsaInVecExt, PsaOutVecExt},
        psa_call::PsaMsg,
    },
    service::{Info, Service},
};
use core::mem::size_of;
use psa_interface::{self, PsaInVec, PsaOutVec};

/// TF-M attestation message type for token retrieval.
pub const TFM_ATTEST_GET_TOKEN: u32 = 1001;
/// TF-M attestation message type for token size retrieval.
pub const TFM_ATTEST_GET_TOKEN_SIZE: u32 = 1002;

pub const PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32: usize = 32;
pub const PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48: usize = 48;
pub const PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64: usize = 64;

/// Maximum token buffer size used by default TF-M builds.
pub const PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE: usize = 0x250;

/// Maximum size of hardware version in bytes
///
/// Recommended to use the European Article Number format: EAN-13 + '-' + 5
/// https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.html#name-certification-reference
///
pub const CERTIFICATION_REF_MAX_SIZE: usize = 19;

pub trait AttestPlatform {
    /// Get the security lifecycle of the device.
    fn security_lifecycle(&self, buf: &mut [u8]) -> Result<(), StatusCode>;
    /// Get the verification service indicator for initial attestation.
    fn verfication_service(&self, buf: &mut [u8]) -> Result<(), StatusCode>;
    /// Get the name of the profile definition document for initial attestation.
    fn profile_definition(&self, buf: &mut [u8]) -> Result<(), StatusCode>;
    /// Generate or retrieve the 32-byte boot seed value used for initial attestation.
    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), StatusCode>;
    /// Get the implementation ID of the device.
    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), StatusCode>;
    /// Get the hardware version of the device.
    fn cert_ref(&self, buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE]) -> Result<(), StatusCode>;
}

pub struct AttestService<P: AttestPlatform> {
    platform: P,
}

impl<P: AttestPlatform> AttestService<P> {
    pub const fn new(platform: P) -> Self {
        Self { platform }
    }

    fn challenge_size_is_supported(challenge_size: usize) -> bool {
        matches!(
            challenge_size,
            PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32
                | PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48
                | PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64
        )
    }

    /// Safe attestation entry point translated from TF-M's C partition.
    pub fn initial_attest_get_token(
        &self,
        challenge: &[u8],
        token: &mut [u8],
    ) -> Result<usize, StatusCode> {
        if !Self::challenge_size_is_supported(challenge.len()) {
            return Err(StatusCode::InvalidArgument);
        }

        if token.is_empty() {
            return Err(StatusCode::InvalidArgument);
        }

        if token.len() > PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE {
            return Err(StatusCode::BufferTooSmall);
        }

        let encoded_len = encode_initial_attestation_token(challenge, token)?;
        token[encoded_len..].fill(0);
        Ok(encoded_len)
    }

    pub fn initial_attest_get_token_size(
        &self,
        challenge_size: usize,
    ) -> Result<usize, StatusCode> {
        if !Self::challenge_size_is_supported(challenge_size) {
            return Err(StatusCode::InvalidArgument);
        }

        compute_initial_attestation_token_size(challenge_size)
    }

    /// Safe dispatch path that can be used by Rust callers with validated iovecs.
    pub fn dispatch(
        &self,
        msg_type: u32,
        in_vec: &[PsaInVec],
        out_vec: &mut [PsaOutVec],
    ) -> Result<(), StatusCode> {
        if msg_type == psa_interface::AttestationServiceType::GetToken as u32 {
            if in_vec.len() != 1 || out_vec.len() != 1 {
                return Err(StatusCode::InvalidArgument);
            }

            let challenge_len = in_vec[0].len;
            if !Self::challenge_size_is_supported(challenge_len) {
                return Err(StatusCode::InvalidArgument);
            }

            if out_vec[0].len == 0 {
                return Err(StatusCode::InvalidArgument);
            }

            if out_vec[0].len > PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE {
                return Err(StatusCode::BufferTooSmall);
            }

            let mut challenge = [0u8; PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
            in_vec[0].read_into(&mut challenge[..challenge_len])?;

            let token_size = self.initial_attest_get_token_size(challenge_len)?;

            if token_size > out_vec[0].len {
                return Err(StatusCode::BufferTooSmall);
            }

            let mut token = [0u8; PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
            self.initial_attest_get_token(&challenge[..challenge_len], &mut token[..token_size])?;

            out_vec[0].write_from(&token[..token_size])
        } else if msg_type == psa_interface::AttestationServiceType::GetTokenSize as u32 {
            if in_vec.len() != 1 || out_vec.len() != 1 {
                return Err(StatusCode::InvalidArgument);
            }

            if in_vec[0].len != size_of::<usize>() {
                return Err(StatusCode::InvalidArgument);
            }

            let mut challenge_size_bytes = [0u8; size_of::<usize>()];
            in_vec[0].read_into(&mut challenge_size_bytes)?;

            let challenge_size = usize::from_ne_bytes(challenge_size_bytes);
            let token_size = self.initial_attest_get_token_size(challenge_size)?;

            let token_size_bytes = token_size.to_ne_bytes();
            out_vec[0].write_from(&token_size_bytes)
        } else {
            Err(StatusCode::NotSupported)
        }
    }
}

impl<P: AttestPlatform> Service for AttestService<P> {
    fn info(&self) -> Info {
        Info { version: 1 }
    }

    fn call(&self, _msg: PsaMsg) {
        // The trusted pointer-to-slice bridge from PSA iovecs into `dispatch()` is
        // still pending, and this crate intentionally avoids introducing `unsafe`.
    }

    fn init(&mut self) {}

    fn deinit(&mut self) {}
}
