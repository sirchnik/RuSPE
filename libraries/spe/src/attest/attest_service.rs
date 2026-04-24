use crate::{
    attest::cose_token::{
        compute_initial_attestation_token_size, encode_initial_attestation_token,
    },
    psa::psa_call::PsaMsg,
    psa_interface::{PsaInVec, PsaOutVec, PsaStatus},
    service::{Info, Service},
};
use core::mem::size_of;

/// TF-M attestation message type for token retrieval.
pub const TFM_ATTEST_GET_TOKEN: u32 = 1001;
/// TF-M attestation message type for token size retrieval.
pub const TFM_ATTEST_GET_TOKEN_SIZE: u32 = 1002;

pub const PSA_SUCCESS: PsaStatus = 0;
pub const PSA_ERROR_NOT_SUPPORTED: PsaStatus = -134;
pub const PSA_ERROR_INVALID_ARGUMENT: PsaStatus = -135;
pub const PSA_ERROR_BUFFER_TOO_SMALL: PsaStatus = -138;

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
    fn security_lifecycle(&self, buf: &mut [u8]) -> Result<(), PsaStatus>;
    /// Get the verification service indicator for initial attestation.
    fn verfication_service(&self, buf: &mut [u8]) -> Result<(), PsaStatus>;
    /// Get the name of the profile definition document for initial attestation.
    fn profile_definition(&self, buf: &mut [u8]) -> Result<(), PsaStatus>;
    /// Generate or retrieve the 32-byte boot seed value used for initial attestation.
    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), PsaStatus>;
    /// Get the implementation ID of the device.
    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), PsaStatus>;
    /// Get the hardware version of the device.
    fn cert_ref(&self, buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE]) -> Result<(), PsaStatus>;
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
    pub fn initial_attest_get_token(&self, challenge: &[u8], token: &mut [u8]) -> PsaStatus {
        if !Self::challenge_size_is_supported(challenge.len()) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if token.is_empty() {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if token.len() > PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        match encode_initial_attestation_token(challenge, token) {
            Ok(encoded_len) => {
                token[encoded_len..].fill(0);
                PSA_SUCCESS
            }
            Err(status) => status,
        }
    }

    pub fn initial_attest_get_token_size(&self, challenge_size: usize) -> Result<usize, PsaStatus> {
        if !Self::challenge_size_is_supported(challenge_size) {
            return Err(PSA_ERROR_INVALID_ARGUMENT);
        }

        compute_initial_attestation_token_size(challenge_size)
    }

    /// Safe dispatch path that can be used by Rust callers with validated iovecs.
    pub fn dispatch(
        &self,
        msg_type: u32,
        in_vec: &[PsaInVec],
        out_vec: &mut [PsaOutVec],
    ) -> PsaStatus {
        if msg_type == psa_interface::AttestationServiceType::GetToken as u32 {
            if in_vec.len() != 1 || out_vec.len() != 1 {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            let challenge_len = in_vec[0].len;
            if !Self::challenge_size_is_supported(challenge_len) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if out_vec[0].len == 0 {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if out_vec[0].len > PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }

            let mut challenge = [0u8; PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
            if let Err(status) = in_vec[0].read_into(&mut challenge[..challenge_len]) {
                return status;
            }

            let token_size = match self.initial_attest_get_token_size(challenge_len) {
                Ok(size) => size,
                Err(status) => return status,
            };

            if token_size > out_vec[0].len {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }

            let mut token = [0u8; PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
            let status = self
                .initial_attest_get_token(&challenge[..challenge_len], &mut token[..token_size]);
            if status != PSA_SUCCESS {
                return status;
            }

            match out_vec[0].write_from(&token[..token_size]) {
                Ok(()) => PSA_SUCCESS,
                Err(status) => status,
            }
        } else if msg_type == psa_interface::AttestationServiceType::GetTokenSize as u32 {
            if in_vec.len() != 1 || out_vec.len() != 1 {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if in_vec[0].len != size_of::<usize>() {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            let mut challenge_size_bytes = [0u8; size_of::<usize>()];
            if let Err(status) = in_vec[0].read_into(&mut challenge_size_bytes) {
                return status;
            }

            let challenge_size = usize::from_ne_bytes(challenge_size_bytes);
            let token_size = match self.initial_attest_get_token_size(challenge_size) {
                Ok(size) => size,
                Err(status) => return status,
            };

            let token_size_bytes = token_size.to_ne_bytes();
            match out_vec[0].write_from(&token_size_bytes) {
                Ok(()) => return PSA_SUCCESS,
                Err(status) => return status,
            }
        } else {
            return PSA_ERROR_NOT_SUPPORTED;
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
