use crate::{
    psa_interface::{PsaInVec, PsaOutVec, PsaStatus},
    service::{Info, Service},
};

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

pub struct AttestService;

impl AttestService {
    pub const fn new() -> Self {
        Self
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

        // The TF-M implementation creates the token with a stack of helpers from
        // attest_boot_data, attest_token, tfm_attest_hal, tfm_crypto, and t_cose.
        // Those libraries are not available in this Rust crate yet, so the actual
        // token construction is intentionally left out instead of being replaced by
        // a fake backend abstraction.
        //
        // Pseudocode of the missing work:
        //   - initialize the attestation boot data
        //   - encode the nonce claim from `challenge`
        //   - add implementation / instance / lifecycle claims
        //   - sign the token and write it into `token`
        //
        // return PSA_SUCCESS once the above is ported.
        let _ = (challenge, token);
        PSA_ERROR_NOT_SUPPORTED
    }

    pub fn initial_attest_get_token_size(&self, challenge_size: usize) -> Result<usize, PsaStatus> {
        if !Self::challenge_size_is_supported(challenge_size) {
            return Err(PSA_ERROR_INVALID_ARGUMENT);
        }

        // The C implementation derives the exact size from the full token build.
        // That depends on the missing attestation/token libraries, so we do not
        // guess at a synthetic size here.
        Err(PSA_ERROR_NOT_SUPPORTED)
    }

    /// Safe dispatch path that can be used by Rust callers with validated iovecs.
    pub fn dispatch(
        &self,
        ctrl_param: u32,
        in_vec: &[PsaInVec],
        out_vec: &mut [PsaOutVec],
    ) -> PsaStatus {
        match ctrl_param {
            TFM_ATTEST_GET_TOKEN => {
                if in_vec.len() != 1 || out_vec.len() != 1 {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }

                if out_vec[0].len == 0 {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }

                if out_vec[0].len > PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE {
                    return PSA_ERROR_BUFFER_TOO_SMALL;
                }

                // The raw-pointer veneer bridge is still pending, so the caller must
                // provide a higher-level safe entry point before this can become live.
                PSA_ERROR_NOT_SUPPORTED
            }
            TFM_ATTEST_GET_TOKEN_SIZE => {
                if in_vec.len() != 1 || out_vec.len() != 1 {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }

                PSA_ERROR_NOT_SUPPORTED
            }
            _ => PSA_ERROR_NOT_SUPPORTED,
        }
    }
}

impl Default for AttestService {
    fn default() -> Self {
        Self::new()
    }
}

impl Service for AttestService {
    fn info(&self) -> Info {
        Info { version: 1 }
    }

    fn call(&self, ctrl_param: u32, in_vec: *const PsaInVec, out_vec: *mut PsaOutVec) {
        let _ = (ctrl_param, in_vec, out_vec);
        // The trusted pointer-to-slice bridge from PSA iovecs into `dispatch()` is
        // still pending, and this crate intentionally avoids introducing `unsafe`.
    }

    fn init(&mut self) {}

    fn deinit(&mut self) {}
}
