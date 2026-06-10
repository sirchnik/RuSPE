// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::attest::psa_token::{
    AttestClaim, AttestClaimValue, IatClaim, SwComponent, compute_initial_attestation_token_size,
    encode_initial_attestation_token,
};
use core::mem::size_of;
use psa_interface::status::StatusCode;
use spe::{
    psa::{psa_api, psa_call::PsaMsg},
    service::{Info, Service},
};

/// Maximum token buffer size used by default TF-M builds.
pub const PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE: usize = 0x250;

/// Maximum size of hardware version in bytes
///
/// Recommended to use the European Article Number format: EAN-13 + '-' + 5
/// https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.html#name-certification-reference
///
pub const CERTIFICATION_REF_MAX_SIZE: usize = 19;

pub trait AttestPlatform {
    /// Get the security lifecycle of the device as a numeric lifecycle code.
    fn security_lifecycle(&self) -> Result<u32, StatusCode>;
    /// Get the verification service indicator (UTF-8 text). Returns number of bytes written.
    fn verification_service(&self, buf: &mut [u8]) -> Result<usize, StatusCode>;
    /// Get the name of the profile definition document (UTF-8 text). Returns number of bytes written.
    fn profile_definition(&self, buf: &mut [u8]) -> Result<usize, StatusCode>;
    /// Generate or retrieve the 32-byte boot seed value used for initial attestation.
    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), StatusCode>;
    /// Get the implementation ID of the device.
    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), StatusCode>;
    /// Get the instance ID (UEID) of the device (33 bytes: 1-byte type + 32-byte ID).
    fn instance_id(&self, buf: &mut [u8; 33]) -> Result<(), StatusCode>;
    /// Get the hardware version (UTF-8 text, EAN-13 format). Returns number of bytes written.
    fn cert_ref(&self, buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE]) -> Result<usize, StatusCode>;
}

/// Upper bound on the number of claims (Nonce + caller-supplied) that can be
/// assembled on the stack for a single attestation token.
const MAX_TOTAL_CLAIMS: usize = 16;

const TEMP_KEY_ID: u32 = 0x1234_5678;

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

        let mut claims_buf = [AttestClaim {
            key: IatClaim::Nonce,
            value: AttestClaimValue::Bytes(&[]),
        }; MAX_TOTAL_CLAIMS];
        let claims = Self::build_claims(challenge, additional_claims, &mut claims_buf)?;

        let encoded_len = encode_initial_attestation_token(claims, token, TEMP_KEY_ID)?;
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

        let dummy_nonce = [0u8; 64];
        let mut claims_buf = [AttestClaim {
            key: IatClaim::Nonce,
            value: AttestClaimValue::Bytes(&[]),
        }; MAX_TOTAL_CLAIMS];
        let claims = Self::build_claims(
            &dummy_nonce[..challenge_size],
            additional_claims,
            &mut claims_buf,
        )?;

        compute_initial_attestation_token_size(claims, TEMP_KEY_ID)
    }

    /// Prepend a Nonce claim to `additional_claims` into `buf` and return
    /// the populated slice.
    fn build_claims<'a>(
        challenge: &'a [u8],
        additional_claims: &[AttestClaim<'a>],
        buf: &'a mut [AttestClaim<'a>; MAX_TOTAL_CLAIMS],
    ) -> Result<&'a [AttestClaim<'a>], StatusCode> {
        let total = additional_claims
            .len()
            .checked_add(1)
            .ok_or(StatusCode::InvalidArgument)?;
        if total > MAX_TOTAL_CLAIMS {
            return Err(StatusCode::InvalidArgument);
        }

        buf[0] = AttestClaim {
            key: IatClaim::Nonce,
            value: AttestClaimValue::Bytes(challenge),
        };
        for (i, c) in additional_claims.iter().enumerate() {
            buf[i + 1] = *c;
        }
        Ok(&buf[..total])
    }

    fn has_exactly_one_iovec(msg: &PsaMsg) -> bool {
        msg.in_size[0].is_some()
            && msg.out_size[0].is_some()
            && msg.in_size[1..].iter().all(Option::is_none)
            && msg.out_size[1..].iter().all(Option::is_none)
    }

    fn build_token_claims<'a>(
        &'a self,
        boot_seed: &'a [u8; 32],
        profile_str: &'a str,
        security_lifecycle: u32,
        verification_str: &'a str,
        cert_ref_str: &'a str,
        impl_id: &'a [u8; 32],
        instance_id: &'a [u8; 33],
    ) -> [AttestClaim<'a>; 9] {
        [
            AttestClaim {
                key: IatClaim::InstanceId,
                value: AttestClaimValue::Bytes(instance_id),
            },
            AttestClaim {
                key: IatClaim::ProfileDefinition,
                value: AttestClaimValue::Text(profile_str),
            },
            AttestClaim {
                key: IatClaim::ClientId,
                value: AttestClaimValue::Signed(1),
            },
            AttestClaim {
                key: IatClaim::SecurityLifecycle,
                value: AttestClaimValue::Unsigned(security_lifecycle as u64),
            },
            AttestClaim {
                key: IatClaim::BootSeed,
                value: AttestClaimValue::Bytes(boot_seed),
            },
            AttestClaim {
                key: IatClaim::SwComponents,
                value: AttestClaimValue::SwComponents(&[SwComponent {
                    measurement_type: None,
                    measurement_value: &[0x03; 32],
                    signer_id: &[0x08; 32],
                }]),
            },
            AttestClaim {
                key: IatClaim::CertificationReference,
                value: AttestClaimValue::Text(cert_ref_str),
            },
            AttestClaim {
                key: IatClaim::ImplementationId,
                value: AttestClaimValue::Bytes(impl_id),
            },
            AttestClaim {
                key: IatClaim::VerificationService,
                value: AttestClaimValue::Text(verification_str),
            },
        ]
    }
}

impl<P: AttestPlatform> Service for AttestService<P> {
    fn info(&self) -> Info {
        Info { version: 1 }
    }

    fn call(&self, msg: PsaMsg) -> Result<(), psa_interface::status::StatusCode> {
        if !Self::has_exactly_one_iovec(&msg) {
            return Err(psa_interface::status::StatusCode::InvalidArgument);
        }

        if msg.msg_type == psa_interface::types::AttestationServiceType::GetToken as i32 {
            let mut boot_seed = [0u8; 32];
            self.platform.boot_seed(&mut boot_seed)?;

            let mut profile_buf = [0u8; 64];
            let profile_len = self.platform.profile_definition(&mut profile_buf)?;
            let profile_str = core::str::from_utf8(&profile_buf[..profile_len])
                .map_err(|_| StatusCode::InvalidArgument)?;

            let security_lifecycle = self.platform.security_lifecycle()?;

            let mut verification_buf = [0u8; 64];
            let verification_len = self.platform.verification_service(&mut verification_buf)?;
            let verification_str = core::str::from_utf8(&verification_buf[..verification_len])
                .map_err(|_| StatusCode::InvalidArgument)?;

            let mut cert_ref_buf = [0u8; CERTIFICATION_REF_MAX_SIZE];
            let cert_ref_len = self.platform.cert_ref(&mut cert_ref_buf)?;
            let cert_ref_str = core::str::from_utf8(&cert_ref_buf[..cert_ref_len])
                .map_err(|_| StatusCode::InvalidArgument)?;

            let mut impl_id = [0u8; 32];
            self.platform.implementation_id(&mut impl_id)?;

            let mut instance_id = [0u8; 33];
            self.platform.instance_id(&mut instance_id)?;

            let additional_claims = self.build_token_claims(
                &boot_seed,
                profile_str,
                security_lifecycle,
                verification_str,
                cert_ref_str,
                &impl_id,
                &instance_id,
            );

            let mut token = [0u8; PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
            let written_len = psa_api::psa_map_invec(msg.handle, 0, |challenge| {
                if !Self::challenge_size_is_supported(challenge.len()) {
                    return Err(StatusCode::InvalidArgument);
                }
                self.initial_attest_get_token(challenge, &additional_claims, &mut token)
            })?;
            psa_api::psa_map_outvec(msg.handle, 0, |outvec| {
                if outvec.len() < written_len {
                    outvec.fill(0);
                    (Err(StatusCode::BufferTooSmall), 0)
                } else {
                    outvec[..written_len].copy_from_slice(&token[..written_len]);
                    (Ok(()), written_len)
                }
            })?;
            Ok(())
        } else if msg.msg_type == psa_interface::types::AttestationServiceType::GetTokenSize as i32
        {
            let challenge_size = psa_api::psa_map_invec(msg.handle, 0, |challenge_size_buf| {
                if challenge_size_buf.len() != size_of::<usize>() {
                    return Err(StatusCode::InvalidArgument);
                }
                let mut challenge_size_array = [0u8; size_of::<usize>()];
                challenge_size_array.copy_from_slice(challenge_size_buf);
                Ok(usize::from_ne_bytes(challenge_size_array))
            })?;

            let mut boot_seed = [0u8; 32];
            self.platform.boot_seed(&mut boot_seed)?;

            let additional_claims = [AttestClaim {
                key: IatClaim::BootSeed,
                value: AttestClaimValue::Bytes(&boot_seed),
            }];

            let token_size =
                self.initial_attest_get_token_size(challenge_size, &additional_claims)?;

            let token_size_bytes = token_size.to_ne_bytes();
            psa_api::psa_map_outvec(msg.handle, 0, |outvec| {
                if outvec.len() < token_size_bytes.len() {
                    outvec.fill(0);
                    (Err(StatusCode::BufferTooSmall), 0)
                } else {
                    outvec[..token_size_bytes.len()].copy_from_slice(&token_size_bytes);
                    (Ok(()), token_size_bytes.len())
                }
            })?;
            Ok(())
        } else {
            Err(psa_interface::status::StatusCode::NotSupported)
        }
    }

    fn init(&mut self) -> Result<(), psa_interface::status::StatusCode> {
        Ok(())
    }

    fn deinit(&mut self) -> Result<(), psa_interface::status::StatusCode> {
        Ok(())
    }
}
