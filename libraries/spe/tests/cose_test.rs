// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#[cfg(not(target_os = "none"))]
mod tests {
    use spe::cose::{CoseSign1, RustCryptoBackend, Sign1Options, encode_payload_bstr};

    const TEST_PAYLOAD: &[u8] = b"This is the content.";
    const TEST_KEY_ID: &[u8] = b"11";

    // Full COSE_Sign1 message hex:
    // d28443a10126a10442313154546869732069732074686520636f6e74656e742e58405e82a37485b16a77f1a5398d1563e96c4f531ffd867364399d1d1978620d604f58c0ead73dcdec180d3f3dce5c6ca85ca8e15dcdc8269fd8549f6d5c4abc3f62
    const EXPECTED_ENCODED_COSE_SIGN1: &[u8] = &[
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x04, 0x42, 0x31, 0x31, 0x54, 0x54, 0x68, 0x69,
        0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
        0x74, 0x2e, 0x58, 0x40, 0x5e, 0x82, 0xa3, 0x74, 0x85, 0xb1, 0x6a, 0x77, 0xf1, 0xa5, 0x39,
        0x8d, 0x15, 0x63, 0xe9, 0x6c, 0x4f, 0x53, 0x1f, 0xfd, 0x86, 0x73, 0x64, 0x39, 0x9d, 0x1d,
        0x19, 0x78, 0x62, 0x0d, 0x60, 0x4f, 0x58, 0xc0, 0xea, 0xd7, 0x3d, 0xcd, 0xec, 0x18, 0x0d,
        0x3f, 0x3d, 0xce, 0x5c, 0x6c, 0xa8, 0x5c, 0xa8, 0xe1, 0x5d, 0xcd, 0xc8, 0x26, 0x9f, 0xd8,
        0x54, 0x9f, 0x6d, 0x5c, 0x4a, 0xbc, 0x3f, 0x62,
    ];
    const EXPECTED_ENCODED_LEN: usize = 98;
    // Test vector private key (EC2KpD)
    const TEST_PRIVATE_KEY: &[u8] = &[
        0x3d, 0x42, 0x9a, 0x83, 0xef, 0xe3, 0x87, 0x10, 0xab, 0x9a, 0xb4, 0xc0, 0x2c, 0xcb, 0xbe,
        0x0b, 0x87, 0xab, 0x69, 0x36, 0xdd, 0xf4, 0x14, 0x57, 0xea, 0x30, 0xf9, 0x6c, 0xa6, 0xf2,
        0xcd, 0xee,
    ];

    #[test]
    fn encodes_test_vector_from_raw_payload() {
        let backend = RustCryptoBackend;
        let signer = CoseSign1::new(backend, TEST_PRIVATE_KEY, Sign1Options::default())
            .with_key_id(TEST_KEY_ID);
        let mut out = [0u8; 256];

        let encoded = signer
            .encode_from_payload(TEST_PAYLOAD, &mut out)
            .expect("payload should encode");

        assert_eq!(encoded.encoded_len, EXPECTED_ENCODED_LEN);
        assert!(!encoded.payload_is_detached);
        assert_eq!(&out[..encoded.encoded_len], EXPECTED_ENCODED_COSE_SIGN1);
    }

    #[test]
    fn encodes_test_vector_from_payload_bstr() {
        let backend = RustCryptoBackend;
        let signer = CoseSign1::new(backend, TEST_PRIVATE_KEY, Sign1Options::default())
            .with_key_id(TEST_KEY_ID);
        let mut payload_bstr = [0u8; 32];
        let payload_bstr_len = encode_payload_bstr(TEST_PAYLOAD, &mut payload_bstr)
            .expect("payload bstr should encode");
        let mut out = [0u8; 256];

        let encoded = signer
            .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], &mut out)
            .expect("payload bstr should encode");

        assert_eq!(encoded.encoded_len, EXPECTED_ENCODED_LEN);
        assert!(!encoded.payload_is_detached);
        assert_eq!(&out[..encoded.encoded_len], EXPECTED_ENCODED_COSE_SIGN1);
    }
}
