use crate::{
    StatusCode,
    attest::cose_token::{
        AttestClaim, AttestClaimValue, IatClaim, compute_initial_attestation_token_size,
        encode_initial_attestation_token,
    },
    psa::{psa_api, psa_call::PsaMsg},
    service::{Info, Service},
};
use core::mem::size_of;
use psa_interface::{self};

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

// Temporary development key used to exercise the token path.
const TEMP_KEY: [u8; 32] = [
    0x3d, 0x42, 0x9a, 0x83, 0xef, 0xe3, 0x87, 0x10, 0xab, 0x9a, 0xb4, 0xc0, 0x2c, 0xcb, 0xbe, 0x0b,
    0x87, 0xab, 0x69, 0x36, 0xdd, 0xf4, 0x14, 0x57, 0xea, 0x30, 0xf9, 0x6c, 0xa6, 0xf2, 0xcd, 0xee,
];

pub struct AttestService<P: AttestPlatform> {
    platform: P,
}

impl<P: AttestPlatform> AttestService<P> {
    pub const fn new(platform: P) -> Self {
        Self { platform }
    }

    fn challenge_size_is_supported(challenge_size: usize) -> bool {
        matches!(challenge_size, 32 | 48 | 64)
    }

    /// Safe attestation entry point translated from TF-M's C partition.
    pub fn initial_attest_get_token(
        &self,
        challenge: &[u8],
        additional_claims: &[AttestClaim<'_>],
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

        let encoded_len =
            encode_initial_attestation_token(challenge, additional_claims, token, &TEMP_KEY)?;
        token[encoded_len..].fill(0);
        Ok(encoded_len)
    }

    pub fn initial_attest_get_token_size(
        &self,
        challenge_size: usize,
        additional_claims: &[AttestClaim<'_>],
    ) -> Result<usize, StatusCode> {
        if !Self::challenge_size_is_supported(challenge_size) {
            return Err(StatusCode::InvalidArgument);
        }

        compute_initial_attestation_token_size(challenge_size, additional_claims, &TEMP_KEY)
    }

    fn has_exactly_one_iovec(msg: &PsaMsg) -> bool {
        msg.in_size[0].is_some()
            && msg.out_size[0].is_some()
            && msg.in_size[1..].iter().all(Option::is_none)
            && msg.out_size[1..].iter().all(Option::is_none)
    }
}

impl<P: AttestPlatform> Service for AttestService<P> {
    fn info(&self) -> Info {
        Info { version: 1 }
    }

    fn call(&self, msg: PsaMsg) -> Result<(), psa_interface::StatusCode> {
        if !Self::has_exactly_one_iovec(&msg) {
            return Err(psa_interface::StatusCode::InvalidArgument);
        }

        if msg.msg_type == psa_interface::AttestationServiceType::GetToken as i32 {
            return psa_api::psa_map_invec_outvec(msg.handle, 0, 0, |challenge, token_buf| {
                let mut written_len = 0;
                let result = (|| -> Result<(), StatusCode> {
                    if !Self::challenge_size_is_supported(challenge.len()) {
                        return Err(StatusCode::InvalidArgument);
                    }

                    if token_buf.is_empty() {
                        return Err(StatusCode::InvalidArgument);
                    }

                    if token_buf.len() > PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE {
                        return Err(StatusCode::BufferTooSmall);
                    }

                    let mut boot_seed = [0u8; 32];
                    self.platform.boot_seed(&mut boot_seed)?;

                    let additional_claims = [AttestClaim {
                        key: IatClaim::BootSeed,
                        value: AttestClaimValue::Bytes(&boot_seed),
                    }];

                    self.initial_attest_get_token(challenge, &additional_claims, token_buf)?;
                    written_len = token_buf.len();
                    Ok(())
                })();

                if result.is_err() {
                    token_buf.fill(0);
                    written_len = 0;
                }

                (result, written_len)
            });
        } else if msg.msg_type == psa_interface::AttestationServiceType::GetTokenSize as i32 {
            return psa_api::psa_map_invec_outvec(
                msg.handle,
                0,
                0,
                |challenge_size_bytes, out_buf| {
                    let mut written_len = 0;
                    let result = (|| -> Result<(), StatusCode> {
                        if challenge_size_bytes.len() != size_of::<usize>() {
                            return Err(StatusCode::InvalidArgument);
                        }

                        let mut challenge_size = [0u8; size_of::<usize>()];
                        challenge_size.copy_from_slice(challenge_size_bytes);

                        let mut boot_seed = [0u8; 32];
                        self.platform.boot_seed(&mut boot_seed)?;

                        let additional_claims = [AttestClaim {
                            key: IatClaim::BootSeed,
                            value: AttestClaimValue::Bytes(&boot_seed),
                        }];

                        let token_size = self.initial_attest_get_token_size(
                            usize::from_ne_bytes(challenge_size),
                            &additional_claims,
                        )?;

                        let token_size_bytes = token_size.to_ne_bytes();
                        if out_buf.len() < token_size_bytes.len() {
                            return Err(StatusCode::BufferTooSmall);
                        }

                        out_buf[..token_size_bytes.len()].copy_from_slice(&token_size_bytes);
                        written_len = token_size_bytes.len();
                        Ok(())
                    })();

                    if result.is_err() {
                        out_buf.fill(0);
                        written_len = 0;
                    }

                    (result, written_len)
                },
            );
        } else {
            Err(psa_interface::StatusCode::NotSupported)
        }
    }

    fn init(&mut self) -> Result<(), psa_interface::StatusCode> {
        Ok(())
    }

    fn deinit(&mut self) -> Result<(), psa_interface::StatusCode> {
        Ok(())
    }
}
