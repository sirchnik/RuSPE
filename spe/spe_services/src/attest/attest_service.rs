// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Initial Attestation Service Implementation.
//!
//! Provides PSA Initial Attestation service endpoints, claim collection from
//! hardware/boot platform drivers, and COSE-Sign1 token generation for Secure
//! Processing Environments (SPE).

use psa_interface::PsaApiCallInterface;
use psa_interface::status::StatusCode;
use psa_interface::types::AttestationServiceType;
use spe::service::Service;
use spe::spm_api::{MaybeUsize, PsaMsg, SpmApi};

use crate::attest::psa_token::{
    AttestClaim, AttestClaimValue, IatClaim, SwComponent, compute_initial_attestation_token_size,
    encode_initial_attestation_token,
};

/// Maximum token buffer size used by default TF-M builds.
pub const PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE: usize = 0x250;

/// Maximum size of hardware version in bytes.
/// Recommended to use the European Article Number format: EAN-13 + '-' + 5
/// <https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.html#name-certification-reference>
pub const CERTIFICATION_REF_MAX_SIZE: usize = 19;

/// Upper bound on total claims (Nonce + caller-supplied) assembled on stack per
/// token.
const MAX_TOTAL_CLAIMS: usize = 16;
const TEMP_KEY_ID: u32 = 0x1234_5678;
const SHARED_DATA_TLV_INFO_MAGIC: u16 = 0x2016;
const IAS_MEASURE_VALUE_TYPE: u16 = (0x1 << 12) | 0x08;
const IAS_SIGNER_ID_TYPE: u16 = (0x1 << 12) | 0x01;

/// Helper constructor to instantiate an [`AttestClaim`] concisely.
#[inline]
const fn claim<'a>(key: IatClaim, value: AttestClaimValue<'a>) -> AttestClaim<'a> {
    AttestClaim { key, value }
}

/// Constant placeholder used to initialize stack claim buffer arrays.
const EMPTY_CLAIM: AttestClaim<'static> = claim(IatClaim::Nonce, AttestClaimValue::Bytes(&[]));

/// Interface provided by the underlying hardware platform for retrieving
/// attestation claims.
pub trait AttestPlatform {
    /// Get the security lifecycle of the device as a numeric lifecycle code.
    fn security_lifecycle(&self) -> Result<u32, StatusCode>;

    /// Get the verification service indicator (UTF-8 text). Returns number of
    /// bytes written.
    fn verification_service(&self, buf: &mut [u8]) -> Result<usize, StatusCode>;

    /// Get the name of the profile definition document (UTF-8 text). Returns
    /// number of bytes written.
    fn profile_definition(&self, buf: &mut [u8]) -> Result<usize, StatusCode>;

    /// Generate or retrieve the 32-byte boot seed value used for initial
    /// attestation.
    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), StatusCode>;

    /// Get the implementation ID of the device.
    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), StatusCode>;

    /// Get the instance ID (UEID) of the device (33 bytes: 1-byte type +
    /// 32-byte ID).
    fn instance_id(&self, buf: &mut [u8; 33]) -> Result<(), StatusCode>;

    /// Get the hardware version (UTF-8 text, EAN-13 format). Returns number of
    /// bytes written.
    fn cert_ref(&self, buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE]) -> Result<usize, StatusCode>;

    /// Get the raw boot record (TLV) shared by the bootloader.
    fn boot_record(&self) -> Option<&'static [u8]>;
}

/// Helper function to parse 16-bit little-endian integers from slice data.
#[inline]
fn get_u16_le(data: &[u8]) -> Option<u16> {
    data.get(..2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

/// Parse UTF-8 text claim payload from slice buffer.
fn parse_utf8_claim(buf: &[u8], len: usize) -> Result<&str, StatusCode> {
    core::str::from_utf8(buf.get(..len).ok_or(StatusCode::InvalidArgument)?)
        .map_err(|_| StatusCode::InvalidArgument)
}

/// Parse raw TLV shared bootloader measurement and signer ID records into a
/// software component.
fn parse_boot_data(data: &[u8]) -> Option<SwComponent<'_>> {
    let magic = get_u16_le(data)?;
    let tot_len = usize::from(get_u16_le(data.get(2..)?)?);
    if magic != SHARED_DATA_TLV_INFO_MAGIC || tot_len > data.len() || tot_len < 4 {
        return None;
    }
    let mut measure_val = None;
    let mut signer_id = None;
    let mut offset = 4;
    while offset + 4 <= tot_len {
        let tlv_type = get_u16_le(data.get(offset..)?)?;
        let tlv_len = usize::from(get_u16_le(data.get(offset + 2..)?)?);
        offset += 4;
        let payload = data.get(offset..offset + tlv_len)?;
        match tlv_type {
            IAS_MEASURE_VALUE_TYPE => measure_val = Some(payload),
            IAS_SIGNER_ID_TYPE => signer_id = Some(payload),
            _ => {}
        }
        offset += tlv_len;
    }
    Some(SwComponent {
        measurement_type: None,
        measurement_value: measure_val?,
        signer_id: signer_id?,
    })
}

/// Stack buffer container holding raw byte arrays for platform claim
/// collection.
struct PlatformBuffers<'a> {
    boot_seed: [u8; 32],
    profile: [u8; 64],
    verification: [u8; 64],
    cert_ref: [u8; CERTIFICATION_REF_MAX_SIZE],
    impl_id: [u8; 32],
    instance_id: [u8; 33],
    sw_component: Option<SwComponent<'a>>,
}

impl<'a> PlatformBuffers<'a> {
    /// Create uninitialized platform buffer container.
    const fn new() -> Self {
        Self {
            boot_seed: [0u8; 32],
            profile: [0u8; 64],
            verification: [0u8; 64],
            cert_ref: [0u8; CERTIFICATION_REF_MAX_SIZE],
            impl_id: [0u8; 32],
            instance_id: [0u8; 33],
            sw_component: None,
        }
    }

    /// Query platform driver and collect array of 9 standard initial
    /// attestation claims.
    fn collect(
        &'a mut self,
        platform: &'a impl AttestPlatform,
    ) -> Result<[AttestClaim<'a>; 9], StatusCode> {
        platform.boot_seed(&mut self.boot_seed)?;
        platform.implementation_id(&mut self.impl_id)?;
        platform.instance_id(&mut self.instance_id)?;
        let sec_lc = platform.security_lifecycle()?;

        let prof_len = platform.profile_definition(&mut self.profile)?;
        let prof_str = parse_utf8_claim(&self.profile, prof_len)?;

        let verif_len = platform.verification_service(&mut self.verification)?;
        let verif_str = parse_utf8_claim(&self.verification, verif_len)?;

        let cert_len = platform.cert_ref(&mut self.cert_ref)?;
        let cert_str = parse_utf8_claim(&self.cert_ref, cert_len)?;

        self.sw_component = platform.boot_record().and_then(parse_boot_data);

        Ok([
            claim(
                IatClaim::InstanceId,
                AttestClaimValue::Bytes(&self.instance_id),
            ),
            claim(
                IatClaim::ProfileDefinition,
                AttestClaimValue::Text(prof_str),
            ),
            claim(IatClaim::ClientId, AttestClaimValue::Signed(1)),
            claim(
                IatClaim::SecurityLifecycle,
                AttestClaimValue::Unsigned(u64::from(sec_lc)),
            ),
            claim(IatClaim::BootSeed, AttestClaimValue::Bytes(&self.boot_seed)),
            claim(
                IatClaim::SwComponents,
                AttestClaimValue::SwComponents(self.sw_component.as_slice()),
            ),
            claim(
                IatClaim::CertificationReference,
                AttestClaimValue::Text(cert_str),
            ),
            claim(
                IatClaim::ImplementationId,
                AttestClaimValue::Bytes(&self.impl_id),
            ),
            claim(
                IatClaim::VerificationService,
                AttestClaimValue::Text(verif_str),
            ),
        ])
    }
}

/// Initial Attestation Service instance implementation.
pub struct AttestService<P: AttestPlatform, C: psa_interface::PsaApiCallInterface> {
    platform: P,
    _marker: core::marker::PhantomData<C>,
}

impl<P: AttestPlatform, C: psa_interface::PsaApiCallInterface> AttestService<P, C> {
    /// Service interface version identifier.
    pub const VERSION: u32 = 1;

    /// Create new initial attestation service instance for specified platform.
    pub const fn new(platform: P) -> Self {
        Self {
            platform,
            _marker: core::marker::PhantomData,
        }
    }

    /// Check if challenge byte length matches supported sizes (32, 48, or 64
    /// bytes).
    const fn challenge_size_is_supported(challenge_size: usize) -> bool {
        matches!(challenge_size, 32 | 48 | 64)
    }

    /// Build and encode initial attestation token for caller request.
    pub fn initial_attest_get_token(
        &self,
        challenge: &[u8],
        additional_claims: &[AttestClaim<'_>],
        token: &mut [u8],
    ) -> Result<usize, StatusCode> {
        if !Self::challenge_size_is_supported(challenge.len()) {
            return Err(StatusCode::InvalidArgument);
        }
        let mut claims_buf = [EMPTY_CLAIM; MAX_TOTAL_CLAIMS];
        let claims = Self::build_claims(challenge, additional_claims, &mut claims_buf)?;
        let encoded_len = encode_initial_attestation_token::<C>(claims, token, TEMP_KEY_ID)?;
        if let Some(rest) = token.get_mut(encoded_len..) {
            rest.fill(0);
        }
        Ok(encoded_len)
    }

    /// Compute exact encoded byte length of initial attestation token for given
    /// challenge size.
    pub fn initial_attest_get_token_size(
        &self,
        challenge_size: usize,
        additional_claims: &[AttestClaim<'_>],
    ) -> Result<usize, StatusCode> {
        if !Self::challenge_size_is_supported(challenge_size) {
            return Err(StatusCode::InvalidArgument);
        }
        let dummy_nonce = [0u8; 64];
        let nonce_slice = dummy_nonce
            .get(..challenge_size)
            .ok_or(StatusCode::InvalidArgument)?;
        let mut claims_buf = [EMPTY_CLAIM; MAX_TOTAL_CLAIMS];
        let claims = Self::build_claims(nonce_slice, additional_claims, &mut claims_buf)?;
        compute_initial_attestation_token_size(claims, TEMP_KEY_ID)
    }

    /// Assemble combined slice of challenge nonce claim and custom claims.
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
        if let Some((first, rest)) = buf.get_mut(..total).and_then(|s| s.split_first_mut()) {
            *first = claim(IatClaim::Nonce, AttestClaimValue::Bytes(challenge));
            rest.copy_from_slice(additional_claims);
            Ok(&buf[..total])
        } else {
            Err(StatusCode::InvalidArgument)
        }
    }

    /// Validate message structure contains exactly one input vector and one
    /// output vector.
    fn has_exactly_one_iovec(msg: &PsaMsg) -> bool {
        msg.in_size.first().and_then(|s| s.as_option()).is_some()
            && msg.out_size.first().and_then(|s| s.as_option()).is_some()
            && msg
                .in_size
                .get(1..)
                .map_or(false, |s| s.iter().all(MaybeUsize::is_none))
            && msg
                .out_size
                .get(1..)
                .map_or(false, |s| s.iter().all(MaybeUsize::is_none))
    }

    /// Handler function for PSA `initial_attest_get_token` requests.
    fn handle_get_token(&self, msg: &PsaMsg, api: &impl SpmApi) -> Result<(), StatusCode> {
        let mut bufs = PlatformBuffers::new();
        let claims = bufs.collect(&self.platform)?;
        api.access_invec_outvec(msg.handle, 0, 0, |challenge, outvec| {
            match self.initial_attest_get_token(challenge, &claims, outvec) {
                Ok(written_len) => (Ok(()), written_len),
                Err(e) => {
                    outvec.fill(0);
                    (Err(e), 0)
                }
            }
        })??;
        Ok(())
    }

    /// Handler function for PSA `initial_attest_get_token_size` requests.
    fn handle_get_token_size(&self, msg: &PsaMsg, api: &impl SpmApi) -> Result<(), StatusCode> {
        let challenge_size = api.access_invec(msg.handle, 0, |buf| {
            buf.get(..core::mem::size_of::<usize>())
                .and_then(|s| s.try_into().ok())
                .map(usize::from_ne_bytes)
                .ok_or(StatusCode::InvalidArgument)
        })??;
        let mut boot_seed = [0u8; 32];
        self.platform.boot_seed(&mut boot_seed)?;
        let parsed_comp = self.platform.boot_record().and_then(parse_boot_data);
        let additional_claims = [
            claim(IatClaim::BootSeed, AttestClaimValue::Bytes(&boot_seed)),
            claim(
                IatClaim::SwComponents,
                AttestClaimValue::SwComponents(parsed_comp.as_slice()),
            ),
        ];
        let token_size = self.initial_attest_get_token_size(challenge_size, &additional_claims)?;
        let token_size_bytes = token_size.to_ne_bytes();
        api.access_outvec(msg.handle, 0, |outvec| {
            if outvec.len() < token_size_bytes.len() {
                outvec.fill(0);
                (Err(StatusCode::BufferTooSmall), 0)
            } else if let Some(target) = outvec.get_mut(..token_size_bytes.len()) {
                target.copy_from_slice(&token_size_bytes);
                (Ok(()), token_size_bytes.len())
            } else {
                outvec.fill(0);
                (Err(StatusCode::BufferTooSmall), 0)
            }
        })??;
        Ok(())
    }
}

impl<P: AttestPlatform, C: PsaApiCallInterface, A: SpmApi> Service<A> for AttestService<P, C> {
    /// Dispatch incoming SPM service request message.
    fn call(&self, msg: PsaMsg, api: &A) -> Result<(), StatusCode> {
        if !Self::has_exactly_one_iovec(&msg) {
            return Err(StatusCode::InvalidArgument);
        }

        match msg.msg_type {
            t if t == AttestationServiceType::GetToken as i32 => self.handle_get_token(&msg, api),
            t if t == AttestationServiceType::GetTokenSize as i32 => {
                self.handle_get_token_size(&msg, api)
            }
            _ => Err(StatusCode::NotSupported),
        }
    }

    /// Service initialization lifecycle hook.
    fn init(&mut self, _api: &A) -> Result<(), StatusCode> {
        Ok(())
    }

    /// Service de-initialization lifecycle hook.
    fn deinit(&mut self, _api: &A) -> Result<(), StatusCode> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "attest_service_test.rs"]
mod tests;
