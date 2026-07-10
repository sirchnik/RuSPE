// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cose::cose_sign1::CoseSign1Error;
use minicbor::Decoder;

use super::{
    AttestClaim, AttestClaimValue, IatClaim, StatusCode, SwComponent, encode_payload,
    map_cose_error,
};

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
