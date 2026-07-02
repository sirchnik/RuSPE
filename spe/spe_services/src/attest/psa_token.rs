// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cose::cose_sign1::{
    CoseCrypto, CoseSign1, CoseSign1Error, RustCryptoHasher, Sign1Options,
    encode_payload_bstr_in_place,
};
use minicbor::{Encoder, encode::write::Cursor};
use psa_interface::PsaApiCallInterface;
use psa_interface::status::StatusCode;
use psa_interface::{psa_api::psa_sign_hash, types::PSA_ALG_ECDSA_SHA256};
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
        let entries = if comp.measurement_type.is_some() { 3 } else { 2 };
        enc.map(entries)?.u8(5)?.bytes(comp.signer_id)?.u8(2)?.bytes(comp.measurement_value)?;
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
        AttestClaimValue::Bytes(bytes) => { enc.bytes(bytes)?; }
        AttestClaimValue::Text(text) => { enc.str(text)?; }
        AttestClaimValue::Unsigned(value) => { enc.u64(value)?; }
        AttestClaimValue::Signed(value) => { enc.i64(value)?; }
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
    // payload in attest stack as io_vecs cannot be passed to other services (crypto)
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

    // COSE_Sign1 overhead without kid (tag 18 + array + protected + unprotected + signature + sig bstr header) = 73 bytes
    let total_len = payload_bstr_len
        .checked_add(73)
        .ok_or(StatusCode::BufferTooSmall)?;

    Ok(total_len)
}

#[cfg(test)]
mod tests {
    use super::StatusCode;
    use super::{
        AttestClaim, AttestClaimValue, IatClaim, SwComponent, encode_payload, map_cose_error,
    };
    use cose::cose_sign1::CoseSign1Error;
    use minicbor::Decoder;

    // -- encode_payload: single-claim cases ------------------------------

    #[test]
    fn encode_payload_single_bytes_claim() {
        let nonce = [0xAA; 32];
        let claims = [AttestClaim {
            key: IatClaim::Nonce,
            value: AttestClaimValue::Bytes(&nonce),
        }];
        let mut buf = [0u8; 128];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::Nonce as i32);
        assert_eq!(dec.bytes().unwrap(), nonce);
    }

    #[test]
    fn encode_payload_single_text_claim() {
        let claims = [AttestClaim {
            key: IatClaim::ProfileDefinition,
            value: AttestClaimValue::Text("tag:psacertified.org,2023:psa#tfm"),
        }];
        let mut buf = [0u8; 128];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::ProfileDefinition as i32);
        assert_eq!(dec.str().unwrap(), "tag:psacertified.org,2023:psa#tfm");
    }

    #[test]
    fn encode_payload_single_unsigned_claim() {
        let claims = [AttestClaim {
            key: IatClaim::SecurityLifecycle,
            value: AttestClaimValue::Unsigned(0x3000),
        }];
        let mut buf = [0u8; 64];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::SecurityLifecycle as i32);
        assert_eq!(dec.u64().unwrap(), 0x3000);
    }

    #[test]
    fn encode_payload_single_signed_claim() {
        let claims = [AttestClaim {
            key: IatClaim::ClientId,
            value: AttestClaimValue::Signed(-1),
        }];
        let mut buf = [0u8; 64];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::ClientId as i32);
        assert_eq!(dec.i64().unwrap(), -1);
    }

    // -- encode_payload: SwComponents ------------------------------------

    #[test]
    fn encode_payload_sw_component_with_measurement_type() {
        let sw = [SwComponent {
            measurement_type: Some("PRoT"),
            measurement_value: &[0x03; 32],
            signer_id: &[0x04; 32],
        }];
        let claims = [AttestClaim {
            key: IatClaim::SwComponents,
            value: AttestClaimValue::SwComponents(&sw),
        }];
        let mut buf = [0u8; 256];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::SwComponents as i32);
        // array of 1 component
        assert_eq!(dec.array().unwrap(), Some(1));
        // component map has 3 entries when measurement_type is present
        assert_eq!(dec.map().unwrap(), Some(3));
        // signer_id (key 5)
        assert_eq!(dec.u8().unwrap(), 5);
        assert_eq!(dec.bytes().unwrap(), [0x04; 32]);
        // measurement_value (key 2)
        assert_eq!(dec.u8().unwrap(), 2);
        assert_eq!(dec.bytes().unwrap(), [0x03; 32]);
        // measurement_type (key 1)
        assert_eq!(dec.u8().unwrap(), 1);
        assert_eq!(dec.str().unwrap(), "PRoT");
    }

    #[test]
    fn encode_payload_sw_component_without_measurement_type() {
        let sw = [SwComponent {
            measurement_type: None,
            measurement_value: &[0x03],
            signer_id: &[0x08],
        }];
        let claims = [AttestClaim {
            key: IatClaim::SwComponents,
            value: AttestClaimValue::SwComponents(&sw),
        }];
        let mut buf = [0u8; 64];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::SwComponents as i32);
        assert_eq!(dec.array().unwrap(), Some(1));
        // map has 2 entries when measurement_type is None
        assert_eq!(dec.map().unwrap(), Some(2));
        assert_eq!(dec.u8().unwrap(), 5);
        assert_eq!(dec.bytes().unwrap(), [0x08]);
        assert_eq!(dec.u8().unwrap(), 2);
        assert_eq!(dec.bytes().unwrap(), [0x03]);
    }

    #[test]
    fn encode_payload_multiple_sw_components() {
        let sw = [
            SwComponent {
                measurement_type: Some("PRoT"),
                measurement_value: &[0x01],
                signer_id: &[0x02],
            },
            SwComponent {
                measurement_type: None,
                measurement_value: &[0x03],
                signer_id: &[0x04],
            },
        ];
        let claims = [AttestClaim {
            key: IatClaim::SwComponents,
            value: AttestClaimValue::SwComponents(&sw),
        }];
        let mut buf = [0u8; 128];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        let _ = dec.i32().unwrap();
        assert_eq!(dec.array().unwrap(), Some(2));
        // First component: 3 entries (has measurement_type)
        assert_eq!(dec.map().unwrap(), Some(3));
        assert_eq!(dec.u8().unwrap(), 5);
        assert_eq!(dec.bytes().unwrap(), [0x02]);
        assert_eq!(dec.u8().unwrap(), 2);
        assert_eq!(dec.bytes().unwrap(), [0x01]);
        assert_eq!(dec.u8().unwrap(), 1);
        assert_eq!(dec.str().unwrap(), "PRoT");
        // Second component: 2 entries (no measurement_type)
        assert_eq!(dec.map().unwrap(), Some(2));
        assert_eq!(dec.u8().unwrap(), 5);
        assert_eq!(dec.bytes().unwrap(), [0x04]);
        assert_eq!(dec.u8().unwrap(), 2);
        assert_eq!(dec.bytes().unwrap(), [0x03]);
    }

    // -- encode_payload: multi-claim with all value types ----------------

    #[test]
    fn encode_payload_all_claim_types_roundtrip() {
        let nonce = [0x11; 32];
        let boot_seed = [0x22; 32];
        let impl_id = b"acme-implementation-id-00000001\x00";
        let sw = [SwComponent {
            measurement_type: None,
            measurement_value: &[0x03],
            signer_id: &[0x08],
        }];
        let claims = [
            AttestClaim {
                key: IatClaim::Nonce,
                value: AttestClaimValue::Bytes(&nonce),
            },
            AttestClaim {
                key: IatClaim::ProfileDefinition,
                value: AttestClaimValue::Text("tag:psacertified.org,2023:psa#tfm"),
            },
            AttestClaim {
                key: IatClaim::ClientId,
                value: AttestClaimValue::Signed(1),
            },
            AttestClaim {
                key: IatClaim::SecurityLifecycle,
                value: AttestClaimValue::Unsigned(12288),
            },
            AttestClaim {
                key: IatClaim::BootSeed,
                value: AttestClaimValue::Bytes(&boot_seed),
            },
            AttestClaim {
                key: IatClaim::SwComponents,
                value: AttestClaimValue::SwComponents(&sw),
            },
            AttestClaim {
                key: IatClaim::CertificationReference,
                value: AttestClaimValue::Text("1234567890123-12345"),
            },
            AttestClaim {
                key: IatClaim::ImplementationId,
                value: AttestClaimValue::Bytes(impl_id),
            },
            AttestClaim {
                key: IatClaim::VerificationService,
                value: AttestClaimValue::Text("https://psa-verifier.org"),
            },
        ];
        let mut buf = [0u8; 512];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        let map_len = dec.map().unwrap().unwrap();
        assert_eq!(map_len, 9);

        // Nonce -> bytes
        assert_eq!(dec.i32().unwrap(), 10);
        assert_eq!(dec.bytes().unwrap(), nonce);
        // ProfileDefinition -> text
        assert_eq!(dec.i32().unwrap(), 265);
        assert_eq!(dec.str().unwrap(), "tag:psacertified.org,2023:psa#tfm");
        // ClientId -> signed int
        assert_eq!(dec.i32().unwrap(), 2394);
        assert_eq!(dec.i64().unwrap(), 1);
        // SecurityLifecycle -> unsigned int
        assert_eq!(dec.i32().unwrap(), 2395);
        assert_eq!(dec.u64().unwrap(), 12288);
        // BootSeed -> bytes
        assert_eq!(dec.i32().unwrap(), 268);
        assert_eq!(dec.bytes().unwrap(), boot_seed);
        // SwComponents -> array
        assert_eq!(dec.i32().unwrap(), 2399);
        assert_eq!(dec.array().unwrap(), Some(1));
        assert_eq!(dec.map().unwrap(), Some(2));
        assert_eq!(dec.u8().unwrap(), 5);
        let _ = dec.bytes().unwrap();
        assert_eq!(dec.u8().unwrap(), 2);
        let _ = dec.bytes().unwrap();
        // CertificationReference -> text
        assert_eq!(dec.i32().unwrap(), 2398);
        assert_eq!(dec.str().unwrap(), "1234567890123-12345");
        // ImplementationId -> bytes
        assert_eq!(dec.i32().unwrap(), 2396);
        assert_eq!(dec.bytes().unwrap(), impl_id);
        // VerificationService -> text
        assert_eq!(dec.i32().unwrap(), 2400);
        assert_eq!(dec.str().unwrap(), "https://psa-verifier.org");
    }

    // -- encode_payload: edge cases --------------------------------------

    #[test]
    fn encode_payload_empty_claims() {
        let mut buf = [0u8; 16];
        let len = encode_payload(&[], &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(0));
    }

    #[test]
    fn encode_payload_buffer_too_small() {
        let claims = [AttestClaim {
            key: IatClaim::Nonce,
            value: AttestClaimValue::Bytes(&[0xAA; 32]),
        }];
        let mut buf = [0u8; 2]; // Too small for map header + claim
        let result = encode_payload(&claims, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn encode_payload_empty_text_claim() {
        let claims = [AttestClaim {
            key: IatClaim::CertificationReference,
            value: AttestClaimValue::Text(""),
        }];
        let mut buf = [0u8; 32];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::CertificationReference as i32);
        assert_eq!(dec.str().unwrap(), "");
    }

    #[test]
    fn encode_payload_zero_unsigned() {
        let claims = [AttestClaim {
            key: IatClaim::SecurityLifecycle,
            value: AttestClaimValue::Unsigned(0),
        }];
        let mut buf = [0u8; 32];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::SecurityLifecycle as i32);
        assert_eq!(dec.u64().unwrap(), 0);
    }

    #[test]
    fn encode_payload_large_positive_signed() {
        let claims = [AttestClaim {
            key: IatClaim::ClientId,
            value: AttestClaimValue::Signed(i32::MAX as i64),
        }];
        let mut buf = [0u8; 32];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(1));
        assert_eq!(dec.i32().unwrap(), IatClaim::ClientId as i32);
        assert_eq!(dec.i64().unwrap(), i32::MAX as i64);
    }

    // -- map_cose_error --------------------------------------------------

    #[test]
    fn map_cose_error_buffer_too_small() {
        assert_eq!(
            map_cose_error(CoseSign1Error::BufferTooSmall),
            StatusCode::BufferTooSmall
        );
    }

    #[test]
    fn map_cose_error_other_variants() {
        assert_eq!(
            map_cose_error(CoseSign1Error::Unknown),
            StatusCode::InvalidArgument
        );
        assert_eq!(
            map_cose_error(CoseSign1Error::InvalidSigningKey),
            StatusCode::InvalidArgument
        );
        assert_eq!(
            map_cose_error(CoseSign1Error::InvalidPayload),
            StatusCode::InvalidArgument
        );
        assert_eq!(
            map_cose_error(CoseSign1Error::Signature),
            StatusCode::InvalidArgument
        );
        assert_eq!(
            map_cose_error(CoseSign1Error::CborEncoding),
            StatusCode::InvalidArgument
        );
    }

    // -- encode_payload: claim key ordering is preserved -----------------

    #[test]
    fn encode_payload_preserves_claim_order() {
        let claims = [
            AttestClaim {
                key: IatClaim::VerificationService,
                value: AttestClaimValue::Text("first"),
            },
            AttestClaim {
                key: IatClaim::Nonce,
                value: AttestClaimValue::Bytes(&[0x01]),
            },
            AttestClaim {
                key: IatClaim::ClientId,
                value: AttestClaimValue::Signed(42),
            },
        ];
        let mut buf = [0u8; 128];
        let len = encode_payload(&claims, &mut buf).unwrap();

        let mut dec = Decoder::new(&buf[..len]);
        assert_eq!(dec.map().unwrap(), Some(3));
        // Keys come out in the order they were provided, not sorted
        assert_eq!(dec.i32().unwrap(), IatClaim::VerificationService as i32);
        let _ = dec.str().unwrap();
        assert_eq!(dec.i32().unwrap(), IatClaim::Nonce as i32);
        let _ = dec.bytes().unwrap();
        assert_eq!(dec.i32().unwrap(), IatClaim::ClientId as i32);
        assert_eq!(dec.i64().unwrap(), 42);
    }

    use psa_interface::PsaApiCallInterface;
    struct MockPsaClient;
    impl PsaApiCallInterface for MockPsaClient {
        fn psa_framework_version() -> u32 {
            1
        }
        fn psa_version(_service_id: u32) -> u32 {
            1
        }
        fn psa_call(
            _handle: psa_interface::types::ServiceHandle,
            _ctrl_param: psa_interface::types::CtrlParam,
            _in_vec: &[psa_interface::types::FFInVec],
            out_vec: &mut [psa_interface::types::FFOutVec],
        ) -> psa_interface::types::PsaStatus {
            if !out_vec.is_empty() {
                out_vec[0].len = 64;
            }
            0
        }
    }

    #[test]
    fn test_compute_initial_attestation_token_size_matches_actual() {
        use super::{compute_initial_attestation_token_size, encode_initial_attestation_token};

        let nonce = [0x11; 32];
        let boot_seed = [0x22; 32];
        let impl_id = b"acme-implementation-id-00000001\x00";
        let sw = [SwComponent {
            measurement_type: None,
            measurement_value: &[0x03],
            signer_id: &[0x08],
        }];
        let claims = [
            AttestClaim {
                key: IatClaim::Nonce,
                value: AttestClaimValue::Bytes(&nonce),
            },
            AttestClaim {
                key: IatClaim::ProfileDefinition,
                value: AttestClaimValue::Text("tag:psacertified.org,2023:psa#tfm"),
            },
            AttestClaim {
                key: IatClaim::ClientId,
                value: AttestClaimValue::Signed(1),
            },
            AttestClaim {
                key: IatClaim::SecurityLifecycle,
                value: AttestClaimValue::Unsigned(12288),
            },
            AttestClaim {
                key: IatClaim::BootSeed,
                value: AttestClaimValue::Bytes(&boot_seed),
            },
            AttestClaim {
                key: IatClaim::SwComponents,
                value: AttestClaimValue::SwComponents(&sw),
            },
            AttestClaim {
                key: IatClaim::CertificationReference,
                value: AttestClaimValue::Text("1234567890123-12345"),
            },
            AttestClaim {
                key: IatClaim::ImplementationId,
                value: AttestClaimValue::Bytes(impl_id),
            },
            AttestClaim {
                key: IatClaim::VerificationService,
                value: AttestClaimValue::Text("https://psa-verifier.org"),
            },
        ];

        let predicted_size = compute_initial_attestation_token_size(&claims, 0).unwrap();

        let mut out = [0u8; 1024];
        let actual_size =
            encode_initial_attestation_token::<MockPsaClient>(&claims, &mut out, 0).unwrap();

        assert_eq!(
            predicted_size, actual_size,
            "Predicted size {} does not match actual encoded token size {}",
            predicted_size, actual_size
        );
    }
}
