// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cose::cose_sign1::{
    CoseCrypto, CoseSign1, CoseSign1Error, RustCryptoHasher, Sign1Options,
    encode_payload_bstr_in_place,
};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use psa_interface::PsaApiCallInterface;
use psa_interface::psa_api::psa_sign_hash;
use psa_interface::status::StatusCode;
use psa_interface::types::PSA_ALG_ECDSA_SHA256;
use sha2::{Digest, Sha256};

/// PSA / EAT claim labels per RFC 9783 Section 6.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IatClaim {
    Nonce = 10,
    InstanceId = 256,
    ProfileDefinition = 265,
    BootSeed = 268,
    ClientId = 2394,
    SecurityLifecycle = 2395,
    ImplementationId = 2396,
    CertificationReference = 2398,
    SwComponents = 2399,
    VerificationService = 2400,
}

/// One PSA software component (RFC 9783 Section 4.4.1).
///
/// Fields are emitted in the order used by the RFC examples:
/// signer-id (5), measurement-value (2), measurement-type (1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwComponent<'a> {
    pub measurement_type: Option<&'a str>,
    pub measurement_value: &'a [u8],
    pub signer_id: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestClaimValue<'a> {
    Bytes(&'a [u8]),
    Text(&'a str),
    Unsigned(u64),
    Signed(i64),
    SwComponents(&'a [SwComponent<'a>]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestClaim<'a> {
    pub key: IatClaim,
    pub value: AttestClaimValue<'a>,
}

fn map_cose_error(err: CoseSign1Error) -> StatusCode {
    match err {
        CoseSign1Error::BufferTooSmall => StatusCode::BufferTooSmall,
        _ => StatusCode::InvalidArgument,
    }
}

fn encode_sw_components<W: minicbor::encode::Write>(
    enc: &mut Encoder<W>,
    components: &[SwComponent<'_>],
) -> Result<(), minicbor::encode::Error<W::Error>> {
    enc.array(components.len() as u64)?;
    for comp in components {
        let entries = if comp.measurement_type.is_some() {
            3
        } else {
            2
        };
        enc.map(entries)?
            .u8(5)?
            .bytes(comp.signer_id)?
            .u8(2)?
            .bytes(comp.measurement_value)?;
        if let Some(mt) = comp.measurement_type {
            enc.u8(1)?.str(mt)?;
        }
    }
    Ok(())
}

fn encode_claim_value<W: minicbor::encode::Write>(
    enc: &mut Encoder<W>,
    value: AttestClaimValue<'_>,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    match value {
        AttestClaimValue::Bytes(bytes) => {
            enc.bytes(bytes)?;
        }
        AttestClaimValue::Text(text) => {
            enc.str(text)?;
        }
        AttestClaimValue::Unsigned(value) => {
            enc.u64(value)?;
        }
        AttestClaimValue::Signed(value) => {
            enc.i64(value)?;
        }
        AttestClaimValue::SwComponents(components) => encode_sw_components(enc, components)?,
    }
    Ok(())
}

fn encode_payload_to<W: minicbor::encode::Write>(
    claims: &[AttestClaim<'_>],
    enc: &mut Encoder<W>,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    enc.map(claims.len() as u64)?;
    for claim in claims {
        enc.i32(claim.key as i32)?;
        encode_claim_value(enc, claim.value)?;
    }
    Ok(())
}

fn encode_payload(claims: &[AttestClaim<'_>], out: &mut [u8]) -> Result<usize, StatusCode> {
    let mut enc = Encoder::new(Cursor::new(out));
    encode_payload_to(claims, &mut enc).map_err(|_| StatusCode::BufferTooSmall)?;
    Ok(enc.writer().position())
}

struct PsaCryptoBackend<C: PsaApiCallInterface> {
    key_id: u32,
    _marker: core::marker::PhantomData<C>,
}

impl<C: PsaApiCallInterface> PsaCryptoBackend<C> {
    const fn new(key_id: u32) -> Self {
        Self {
            key_id,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<C: PsaApiCallInterface> CoseCrypto for PsaCryptoBackend<C> {
    type Hasher = RustCryptoHasher;

    fn hasher_sha256(&self) -> Self::Hasher {
        RustCryptoHasher(Sha256::new())
    }

    fn sign_es256_prehash(&self, digest: &[u8; 32]) -> Result<[u8; 64], CoseSign1Error> {
        let mut signature = [0u8; 64];
        match psa_sign_hash::<C>(self.key_id, PSA_ALG_ECDSA_SHA256, digest, &mut signature) {
            Ok(written_len) => {
                if written_len == signature.len() {
                    return Ok(signature);
                }
                Err(CoseSign1Error::BufferTooSmall)
            }
            Err(status) => {
                if status == StatusCode::BufferTooSmall {
                    return Err(CoseSign1Error::BufferTooSmall);
                }
                Err(CoseSign1Error::Unknown)
            }
        }
    }
}

pub fn encode_initial_attestation_token<C: PsaApiCallInterface>(
    claims: &[AttestClaim<'_>],
    token: &mut [u8],
    key_id: u32,
) -> Result<usize, StatusCode> {
    // payload in attest stack as io_vecs cannot be passed to other services
    // (crypto)
    let mut payload_buf = [0u8; 512];
    let payload_len = encode_payload(claims, &mut payload_buf)?;
    let payload_bstr_len =
        encode_payload_bstr_in_place(payload_len, &mut payload_buf).map_err(map_cose_error)?;

    let signer = CoseSign1::new(PsaCryptoBackend::<C>::new(key_id), Sign1Options::default());

    let encoded = signer
        .encode_from_payload_bstr(&payload_buf[..payload_bstr_len], token)
        .map_err(map_cose_error)?;

    Ok(encoded.encoded_len)
}

#[derive(Default)]
struct SizeCounter {
    len: usize,
}

impl minicbor::encode::Write for SizeCounter {
    type Error = core::convert::Infallible;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.len = self.len.saturating_add(buf.len());
        Ok(())
    }
}

pub fn compute_initial_attestation_token_size(
    claims: &[AttestClaim<'_>],
    _key_id: u32,
) -> Result<usize, StatusCode> {
    let mut counter = SizeCounter::default();
    let mut enc = Encoder::new(&mut counter);
    encode_payload_to(claims, &mut enc).map_err(|_| StatusCode::BufferTooSmall)?;

    let payload_len = counter.len;

    // CBOR bstr header length for the payload
    let bstr_header_len = if payload_len <= 23 {
        1
    } else if payload_len <= 0xff {
        2
    } else if payload_len <= 0xffff {
        3
    } else if payload_len <= 0xffff_ffff {
        5
    } else {
        9
    };

    let payload_bstr_len = payload_len
        .checked_add(bstr_header_len)
        .ok_or(StatusCode::BufferTooSmall)?;

    // COSE_Sign1 overhead without kid (tag 18 + array + protected + unprotected +
    // signature + sig bstr header) = 73 bytes
    let total_len = payload_bstr_len
        .checked_add(73)
        .ok_or(StatusCode::BufferTooSmall)?;

    Ok(total_len)
}

#[cfg(test)]
#[path = "psa_token_test.rs"]
mod tests;
