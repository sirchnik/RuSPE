use crate::{
    StatusCode,
    cose::{CoseSign1, CoseSign1Error, RustCryptoBackend, Sign1Options, encode_payload_bstr},
};
use minicbor::{Encoder, encode::write::Cursor};

/// PSA / EAT claim labels per RFC 9783 §6.
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

/// One PSA software component (RFC 9783 §4.4.1).
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

const MAX_PAYLOAD_SIZE: usize = crate::attest::attest_service::PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE;
const MAX_ENCODED_PAYLOAD_BSTR_SIZE: usize = MAX_PAYLOAD_SIZE + 9;

fn map_cose_error(err: CoseSign1Error) -> StatusCode {
    match err {
        CoseSign1Error::BufferTooSmall => StatusCode::BufferTooSmall,
        _ => StatusCode::InvalidArgument,
    }
}

fn encode_sw_components(
    enc: &mut Encoder<Cursor<&mut [u8]>>,
    components: &[SwComponent<'_>],
) -> Result<(), StatusCode> {
    enc.array(components.len() as u64)
        .map_err(|_| StatusCode::BufferTooSmall)?;
    for comp in components {
        let mut entries: u64 = 2;
        if comp.measurement_type.is_some() {
            entries += 1;
        }
        enc.map(entries)
            .map_err(|_| StatusCode::BufferTooSmall)?
            .u8(5)
            .map_err(|_| StatusCode::BufferTooSmall)?
            .bytes(comp.signer_id)
            .map_err(|_| StatusCode::BufferTooSmall)?
            .u8(2)
            .map_err(|_| StatusCode::BufferTooSmall)?
            .bytes(comp.measurement_value)
            .map_err(|_| StatusCode::BufferTooSmall)?;
        if let Some(mt) = comp.measurement_type {
            enc.u8(1)
                .map_err(|_| StatusCode::BufferTooSmall)?
                .str(mt)
                .map_err(|_| StatusCode::BufferTooSmall)?;
        }
    }
    Ok(())
}

fn encode_claim_value<'a>(
    enc: &mut Encoder<Cursor<&mut [u8]>>,
    value: AttestClaimValue<'a>,
) -> Result<(), StatusCode> {
    match value {
        AttestClaimValue::Bytes(bytes) => {
            enc.bytes(bytes).map_err(|_| StatusCode::BufferTooSmall)?;
        }
        AttestClaimValue::Text(text) => {
            enc.str(text).map_err(|_| StatusCode::BufferTooSmall)?;
        }
        AttestClaimValue::Unsigned(value) => {
            enc.u64(value).map_err(|_| StatusCode::BufferTooSmall)?;
        }
        AttestClaimValue::Signed(value) => {
            enc.i64(value).map_err(|_| StatusCode::BufferTooSmall)?;
        }
        AttestClaimValue::SwComponents(components) => {
            encode_sw_components(enc, components)?;
        }
    }

    Ok(())
}

fn encode_payload(claims: &[AttestClaim<'_>], out: &mut [u8]) -> Result<usize, StatusCode> {
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(claims.len() as u64)
        .map_err(|_| StatusCode::BufferTooSmall)?;

    for claim in claims {
        enc.i32(claim.key as i32)
            .map_err(|_| StatusCode::BufferTooSmall)?;
        encode_claim_value(&mut enc, claim.value)?;
    }

    Ok(enc.writer().position())
}

/// Encode a COSE_Sign1-protected PSA initial attestation token.
///
/// The caller is responsible for including the `Nonce` claim in `claims` if
/// the profile requires it. No `kid` is emitted in the unprotected header.
pub fn encode_initial_attestation_token(
    claims: &[AttestClaim<'_>],
    token: &mut [u8],
    key: &[u8],
) -> Result<usize, StatusCode> {
    let mut payload = [0u8; MAX_PAYLOAD_SIZE];
    let payload_len = encode_payload(claims, &mut payload)?;

    let mut payload_bstr = [0u8; MAX_ENCODED_PAYLOAD_BSTR_SIZE];
    let payload_bstr_len =
        encode_payload_bstr(&payload[..payload_len], &mut payload_bstr).map_err(map_cose_error)?;

    let signer = CoseSign1::new(RustCryptoBackend, key, Sign1Options::default());

    let encoded = signer
        .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], token)
        .map_err(map_cose_error)?;

    Ok(encoded.encoded_len)
}

pub fn compute_initial_attestation_token_size(
    claims: &[AttestClaim<'_>],
    key: &[u8],
) -> Result<usize, StatusCode> {
    let mut token = [0u8; crate::attest::attest_service::PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
    encode_initial_attestation_token(claims, &mut token, key)
}

#[cfg(test)]
mod tests {
    use super::{
        AttestClaim, AttestClaimValue, IatClaim, SwComponent,
        compute_initial_attestation_token_size, encode_initial_attestation_token,
    };
    use minicbor::Decoder;

    const TEST_PRIVATE_KEY: &[u8] = &[
        0x43, 0xff, 0xfe, 0xcb, 0x95, 0xf8, 0x08, 0x5a, 0x7c, 0x40, 0xe1, 0xd3, 0xea, 0x79, 0x0b,
        0xef, 0x4e, 0xb7, 0x8c, 0xdd, 0x77, 0xd5, 0x85, 0x03, 0xa6, 0x4c, 0x16, 0x00, 0xf9, 0x1b,
        0x33, 0xe7,
    ];

    fn decode_payload_from_token<'a>(token: &'a [u8]) -> &'a [u8] {
        let mut dec = Decoder::new(token);

        let tag = dec.tag().expect("COSE_Sign1 tag should decode");
        assert_eq!(tag.as_u64(), 18);

        let array_len = dec.array().expect("COSE_Sign1 array should decode");
        assert_eq!(array_len, Some(4));

        let _protected_headers = dec.bytes().expect("protected header should decode");

        let unprotected_len = dec.map().expect("unprotected header should decode");
        assert_eq!(unprotected_len, Some(0));

        let payload = dec.bytes().expect("payload should decode");
        let signature = dec.bytes().expect("signature should decode");
        assert_eq!(signature.len(), 64);

        payload
    }

    #[test]
    fn token_payload_contains_only_nonce() {
        let challenge = [0xAB; 32];
        let claims = [AttestClaim {
            key: IatClaim::Nonce,
            value: AttestClaimValue::Bytes(&challenge),
        }];
        let mut token = [0u8; crate::attest::attest_service::PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];

        let encoded_len = encode_initial_attestation_token(&claims, &mut token, TEST_PRIVATE_KEY)
            .expect("token should encode");

        let payload = decode_payload_from_token(&token[..encoded_len]);
        let mut payload_dec = Decoder::new(payload);
        assert_eq!(
            payload_dec.map().expect("payload map should decode"),
            Some(1)
        );
        assert_eq!(
            payload_dec.i32().expect("nonce key should decode"),
            IatClaim::Nonce as i32
        );
        assert_eq!(
            payload_dec.bytes().expect("nonce value should decode"),
            challenge
        );
    }

    #[test]
    fn token_payload_contains_additional_claims() {
        let challenge = [0x11; 32];
        let boot_seed = [0x22; 32];
        let claims = [
            AttestClaim {
                key: IatClaim::Nonce,
                value: AttestClaimValue::Bytes(&challenge),
            },
            AttestClaim {
                key: IatClaim::BootSeed,
                value: AttestClaimValue::Bytes(&boot_seed),
            },
            AttestClaim {
                key: IatClaim::VerificationService,
                value: AttestClaimValue::Text("https://verifier.example"),
            },
            AttestClaim {
                key: IatClaim::SecurityLifecycle,
                value: AttestClaimValue::Unsigned(0x3000),
            },
            AttestClaim {
                key: IatClaim::ClientId,
                value: AttestClaimValue::Signed(-1),
            },
        ];

        let mut token = [0u8; crate::attest::attest_service::PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
        let _ = encode_initial_attestation_token(&claims, &mut token, TEST_PRIVATE_KEY)
            .expect("token should encode");
    }

    #[test]
    fn computed_token_size_matches_encoded_token_size() {
        let challenge = [0x44; 48];
        let boot_seed = [0x55; 32];
        let claims = [
            AttestClaim {
                key: IatClaim::Nonce,
                value: AttestClaimValue::Bytes(&challenge),
            },
            AttestClaim {
                key: IatClaim::BootSeed,
                value: AttestClaimValue::Bytes(&boot_seed),
            },
        ];

        let computed_size = compute_initial_attestation_token_size(&claims, TEST_PRIVATE_KEY)
            .expect("token size should compute");

        let mut token = [0u8; crate::attest::attest_service::PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
        let encoded_len = encode_initial_attestation_token(&claims, &mut token, TEST_PRIVATE_KEY)
            .expect("token should encode");

        assert_eq!(computed_size, encoded_len);
    }

    /// RFC 9783 Appendix A.1 COSE_Sign1 token test vector.
    #[test]
    fn rfc_test_vector() {
        let ueid = [
            0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02,
        ];
        let psa_impl_id = [0u8; 32];
        let eat_nonce = [0x01u8; 32];
        let bootseed = [0u8; 8];
        let signer_id = [0x04u8; 32];
        let measurement_value = [0x03u8; 32];

        let sw_components = [SwComponent {
            measurement_type: Some("PRoT"),
            measurement_value: &measurement_value,
            signer_id: &signer_id,
        }];

        let claims = [
            AttestClaim {
                key: IatClaim::InstanceId,
                value: AttestClaimValue::Bytes(&ueid),
            },
            AttestClaim {
                key: IatClaim::ImplementationId,
                value: AttestClaimValue::Bytes(&psa_impl_id),
            },
            AttestClaim {
                key: IatClaim::Nonce,
                value: AttestClaimValue::Bytes(&eat_nonce),
            },
            AttestClaim {
                key: IatClaim::ClientId,
                value: AttestClaimValue::Signed(2147483647),
            },
            AttestClaim {
                key: IatClaim::SecurityLifecycle,
                value: AttestClaimValue::Unsigned(12288),
            },
            AttestClaim {
                key: IatClaim::ProfileDefinition,
                value: AttestClaimValue::Text("tag:psacertified.org,2023:psa#tfm"),
            },
            AttestClaim {
                key: IatClaim::BootSeed,
                value: AttestClaimValue::Bytes(&bootseed),
            },
            AttestClaim {
                key: IatClaim::SwComponents,
                value: AttestClaimValue::SwComponents(&sw_components),
            },
        ];

        let mut token = [0u8; crate::attest::attest_service::PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
        let encoded_len = encode_initial_attestation_token(&claims, &mut token, TEST_PRIVATE_KEY)
            .expect("token should encode");

        const EXPECTED_TOKEN: &[u8] = &[
            0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x01, 0x00, 0xa8, 0x19, 0x01, 0x00,
            0x58, 0x21, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x19, 0x09, 0x5c, 0x58, 0x20, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0a, 0x58, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x19, 0x09, 0x5a, 0x1a, 0x7f,
            0xff, 0xff, 0xff, 0x19, 0x09, 0x5b, 0x19, 0x30, 0x00, 0x19, 0x01, 0x09, 0x78, 0x21,
            0x74, 0x61, 0x67, 0x3a, 0x70, 0x73, 0x61, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
            0x65, 0x64, 0x2e, 0x6f, 0x72, 0x67, 0x2c, 0x32, 0x30, 0x32, 0x33, 0x3a, 0x70, 0x73,
            0x61, 0x23, 0x74, 0x66, 0x6d, 0x19, 0x01, 0x0c, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x19, 0x09, 0x5f, 0x81, 0xa3, 0x05, 0x58, 0x20, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x04, 0x02, 0x58, 0x20, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x01, 0x64, 0x50, 0x52, 0x6f, 0x54,
            0x58, 0x40, 0x78, 0x6e, 0x93, 0x7a, 0x4c, 0x42, 0x66, 0x7a, 0xf3, 0x84, 0x73, 0x99,
            0x31, 0x9c, 0xa9, 0x5c, 0x7e, 0x7d, 0xba, 0xbd, 0xc9, 0xb5, 0x0f, 0xdb, 0x8d, 0xe3,
            0xf6, 0xbf, 0xf4, 0xab, 0x82, 0xff, 0x80, 0xc4, 0x21, 0x40, 0xe2, 0xa4, 0x88, 0x00,
            0x02, 0x19, 0xe3, 0xe1, 0x06, 0x63, 0x19, 0x3d, 0xa6, 0x9c, 0x75, 0xf5, 0x2b, 0x79,
            0x8e, 0xa1, 0x0b, 0x2f, 0x70, 0x41, 0xa9, 0x0e, 0x8e, 0x5a,
        ];
        assert_eq!(&token[..encoded_len], EXPECTED_TOKEN);
    }
}
