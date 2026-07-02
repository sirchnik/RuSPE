use super::{
    CoseSign1, CoseSign1Error, RustCryptoBackend, Sign1Options, encode_payload_bstr,
    encode_payload_bstr_in_place, validate_payload_bstr,
};

const TEST_PAYLOAD: &[u8] = b"This is the content.";
const TEST_KEY_ID: &[u8] = b"11";

// Full COSE_Sign1 message hex:
// d28443a10126a10442313154546869732069732074686520636f6e74656e742e58405e82a37485b16a77f1a5398d1563e96c4f531ffd867364399d1d1978620d604f58c0ead73dcdec180d3f3dce5c6ca85ca8e15dcdc8269fd8549f6d5c4abc3f62
const EXPECTED_ENCODED_COSE_SIGN1: &[u8] = &[
    0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x04, 0x42, 0x31, 0x31, 0x54, 0x54, 0x68, 0x69, 0x73,
    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e,
    0x58, 0x40, 0x5e, 0x82, 0xa3, 0x74, 0x85, 0xb1, 0x6a, 0x77, 0xf1, 0xa5, 0x39, 0x8d, 0x15, 0x63,
    0xe9, 0x6c, 0x4f, 0x53, 0x1f, 0xfd, 0x86, 0x73, 0x64, 0x39, 0x9d, 0x1d, 0x19, 0x78, 0x62, 0x0d,
    0x60, 0x4f, 0x58, 0xc0, 0xea, 0xd7, 0x3d, 0xcd, 0xec, 0x18, 0x0d, 0x3f, 0x3d, 0xce, 0x5c, 0x6c,
    0xa8, 0x5c, 0xa8, 0xe1, 0x5d, 0xcd, 0xc8, 0x26, 0x9f, 0xd8, 0x54, 0x9f, 0x6d, 0x5c, 0x4a, 0xbc,
    0x3f, 0x62,
];
const EXPECTED_ENCODED_LEN: usize = 98;
// Test vector private key (EC2KpD)
const TEST_PRIVATE_KEY: &[u8] = &[
    0x3d, 0x42, 0x9a, 0x83, 0xef, 0xe3, 0x87, 0x10, 0xab, 0x9a, 0xb4, 0xc0, 0x2c, 0xcb, 0xbe, 0x0b,
    0x87, 0xab, 0x69, 0x36, 0xdd, 0xf4, 0x14, 0x57, 0xea, 0x30, 0xf9, 0x6c, 0xa6, 0xf2, 0xcd, 0xee,
];

fn make_signer<'a>() -> CoseSign1<'a, RustCryptoBackend<'a>> {
    let backend = RustCryptoBackend {
        key: TEST_PRIVATE_KEY,
    };
    CoseSign1::new(backend, Sign1Options::default())
}

fn encode_test_payload_bstr() -> ([u8; 32], usize) {
    let mut buf = [0u8; 32];
    let len = encode_payload_bstr(TEST_PAYLOAD, &mut buf).unwrap();
    (buf, len)
}

#[test]
fn encodes_test_vector_from_payload_bstr() {
    let backend = RustCryptoBackend {
        key: TEST_PRIVATE_KEY,
    };
    let signer = CoseSign1::new(backend, Sign1Options::default()).with_key_id(TEST_KEY_ID);
    let mut payload_bstr = [0u8; 32];
    let payload_bstr_len =
        encode_payload_bstr(TEST_PAYLOAD, &mut payload_bstr).expect("payload bstr should encode");
    let mut out = [0u8; 256];

    let encoded = signer
        .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out)
        .expect("payload bstr should encode");

    assert_eq!(encoded.encoded_len, EXPECTED_ENCODED_LEN);
    assert!(!encoded.payload_is_detached);
    assert_eq!(&out[..encoded.encoded_len], EXPECTED_ENCODED_COSE_SIGN1);
}

#[test]
fn encode_payload_bstr_empty() {
    let mut buf = [0u8; 8];
    let len = encode_payload_bstr(&[], &mut buf).unwrap();
    // CBOR bstr of length 0 is 0x40
    assert_eq!(len, 1);
    assert_eq!(buf[0], 0x40);
}

#[test]
fn encode_payload_bstr_single_byte() {
    let mut buf = [0u8; 8];
    let len = encode_payload_bstr(&[0xAB], &mut buf).unwrap();
    // CBOR bstr of length 1: 0x41 0xAB
    assert_eq!(len, 2);
    assert_eq!(&buf[..len], &[0x41, 0xAB]);
}

#[test]
fn encode_payload_bstr_in_place_moves_payload() {
    let mut buf = [0u8; 8];
    buf[..3].copy_from_slice(b"abc");
    let len = encode_payload_bstr_in_place(3, &mut buf).unwrap();
    assert_eq!(len, 4);
    assert_eq!(&buf[..len], &[0x43, b'a', b'b', b'c']);
}

#[test]
fn encode_payload_bstr_buffer_too_small() {
    let mut buf = [0u8; 1]; // Too small for the header + payload
    let result = encode_payload_bstr(TEST_PAYLOAD, &mut buf);
    assert_eq!(result, Err(CoseSign1Error::BufferTooSmall));
}

#[test]
fn validate_payload_bstr_rejects_empty_input() {
    assert_eq!(
        validate_payload_bstr(&[]),
        Err(CoseSign1Error::InvalidPayload)
    );
}

#[test]
fn validate_payload_bstr_rejects_non_bstr() {
    // 0x01 is CBOR unsigned integer 1, not a bstr
    assert_eq!(
        validate_payload_bstr(&[0x01]),
        Err(CoseSign1Error::InvalidPayload)
    );
}

#[test]
fn validate_payload_bstr_rejects_trailing_bytes() {
    // 0x40 is a valid empty bstr, but 0xFF is trailing
    assert_eq!(
        validate_payload_bstr(&[0x40, 0xFF]),
        Err(CoseSign1Error::InvalidPayload)
    );
}

#[test]
fn validate_payload_bstr_accepts_valid() {
    let mut buf = [0u8; 32];
    let len = encode_payload_bstr(TEST_PAYLOAD, &mut buf).unwrap();
    assert!(validate_payload_bstr(&buf[..len]).is_ok());
}

#[test]
fn encode_without_cbor_tag() {
    let backend = RustCryptoBackend {
        key: TEST_PRIVATE_KEY,
    };
    let opts = Sign1Options {
        omit_cbor_tag: true,
        detached_payload: false,
    };
    let signer = CoseSign1::new(backend, opts);
    let (payload_bstr, payload_bstr_len) = encode_test_payload_bstr();
    let mut out = [0u8; 256];

    let encoded = signer
        .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out)
        .unwrap();

    // Without tag, the first byte should be 0x84 (CBOR array of 4)
    assert_eq!(out[0], 0x84);
    // Should be shorter than the tagged version (tag d2 = 1 byte tag header)
    assert!(encoded.encoded_len < EXPECTED_ENCODED_LEN);
}

#[test]
fn encode_with_detached_payload() {
    let backend = RustCryptoBackend {
        key: TEST_PRIVATE_KEY,
    };
    let opts = Sign1Options {
        omit_cbor_tag: false,
        detached_payload: true,
    };
    let signer = CoseSign1::new(backend, opts).with_key_id(TEST_KEY_ID);
    let (payload_bstr, payload_bstr_len) = encode_test_payload_bstr();
    let mut out = [0u8; 256];

    let encoded = signer
        .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out)
        .unwrap();

    assert!(encoded.payload_is_detached);
    // Detached payload should have null (0xf6) instead of the bstr
    assert!(out[..encoded.encoded_len].contains(&0xf6));
}

#[test]
fn encode_without_key_id() {
    let signer = make_signer();
    let (payload_bstr, payload_bstr_len) = encode_test_payload_bstr();
    let mut out = [0u8; 256];

    let encoded = signer
        .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out)
        .unwrap();

    // Should encode successfully without key_id (empty unprotected header map)
    assert!(encoded.encoded_len > 0);
    assert!(!encoded.payload_is_detached);
}

#[test]
fn encode_buffer_too_small() {
    let signer = make_signer();
    let (payload_bstr, payload_bstr_len) = encode_test_payload_bstr();
    let mut out = [0u8; 4]; // Way too small for a COSE_Sign1

    let result = signer.encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out);

    assert_eq!(result, Err(CoseSign1Error::BufferTooSmall));
}

#[test]
fn invalid_signing_key_returns_error() {
    let backend = RustCryptoBackend { key: &[0xFF; 32] }; // Invalid P-256 key
    let signer = CoseSign1::new(backend, Sign1Options::default());
    let (payload_bstr, payload_bstr_len) = encode_test_payload_bstr();
    let mut out = [0u8; 256];

    let result = signer.encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out);

    assert_eq!(result, Err(CoseSign1Error::InvalidSigningKey));
}

#[test]
fn empty_signing_key_returns_error() {
    let backend = RustCryptoBackend { key: &[] };
    let signer = CoseSign1::new(backend, Sign1Options::default());
    let (payload_bstr, payload_bstr_len) = encode_test_payload_bstr();
    let mut out = [0u8; 256];

    let result = signer.encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out);

    assert_eq!(result, Err(CoseSign1Error::InvalidSigningKey));
}

#[test]
fn with_external_aad() {
    let backend = RustCryptoBackend {
        key: TEST_PRIVATE_KEY,
    };
    let signer =
        CoseSign1::new(backend, Sign1Options::default()).with_external_aad(b"extra context");
    let (payload_bstr, payload_bstr_len) = encode_test_payload_bstr();
    let mut out = [0u8; 256];

    let encoded = signer
        .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out)
        .unwrap();

    // External AAD changes the signature but not the structure
    assert!(encoded.encoded_len > 0);
    // The encoding with AAD should differ from the baseline (different signature)
    assert_ne!(&out[..encoded.encoded_len], EXPECTED_ENCODED_COSE_SIGN1);
}
