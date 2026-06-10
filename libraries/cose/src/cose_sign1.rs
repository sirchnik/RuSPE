// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

//! Minimal COSE_Sign1 parameter encoding support.
//!
//! This module supports only ECDSA with SHA-256 (COSE alg `ES256`, `-7`).

use minicbor::{
    Decoder, Encoder,
    data::Tag,
    encode::Write,
    encode::write::{Cursor, EndOfSlice},
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
enum CoseHeaderLabels {
    Alg = 1,
    ContentType = 3,
    Kid = 4,
    Iv = 5,
    PartialIV = 6,
    CounterSignature = 7,
}

/// CBOR tag for COSE_Sign1.
pub const CBOR_TAG_COSE_SIGN1: u64 = 18;
/// COSE algorithm identifier for ECDSA with SHA-256.
pub const COSE_ALGORITHM_ES256: i32 = -7;

// from RFC
const SIG_CONTEXT_STRING: &str = "Signature1";

/// Errors returned by COSE Sign1 parameter setup/encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoseSign1Error {
    Unknown,
    /// Private key encoding or value is invalid.
    InvalidSigningKey,
    /// The provided encoded payload is not a single CBOR bstr item.
    InvalidPayload,
    /// Output buffer is too small.
    BufferTooSmall,
    /// Signature operation failed.
    Signature,
    /// Generic encoding error.
    CborEncoding,
}

/// Option flags corresponding to t_cose Sign1 behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sign1Options {
    /// Do not emit CBOR tag 18.
    pub omit_cbor_tag: bool,
    /// Emit detached payload (`null`) in COSE_Sign1 payload field.
    ///
    /// The payload bstr is still signed in the `Sig_structure`.
    pub detached_payload: bool,
}

/// Result of encoding COSE_Sign1 parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedParameters {
    /// Number of bytes encoded into the output buffer.
    pub encoded_len: usize,
    /// Whether detached payload mode was used.
    pub payload_is_detached: bool,
}

/// Hash interface used by [`CoseCrypto`] to construct SHA-256 digests.
pub trait CoseHasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; 32];
}

/// Unified crypto abstraction for COSE_Sign1.
///
/// Implementations must provide SHA-256 hashing and ES256 prehash signing.
pub trait CoseCrypto {
    type Hasher: CoseHasher;

    fn hasher_sha256(&self) -> Self::Hasher;

    fn sign_es256_prehash(&self, digest: &[u8; 32]) -> Result<[u8; 64], CoseSign1Error>;
}

/// Default RustCrypto backend using `sha2` and `p256`.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoBackend<'a> {
    key: &'a [u8],
}

pub struct RustCryptoHasher(pub Sha256);

impl CoseHasher for RustCryptoHasher {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        let digest = self.0.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

impl CoseCrypto for RustCryptoBackend<'_> {
    type Hasher = RustCryptoHasher;

    fn hasher_sha256(&self) -> Self::Hasher {
        RustCryptoHasher(Sha256::new())
    }

    fn sign_es256_prehash(&self, digest: &[u8; 32]) -> Result<[u8; 64], CoseSign1Error> {
        let signing_key =
            SigningKey::from_slice(self.key).map_err(|_| CoseSign1Error::InvalidSigningKey)?;
        let signature: Signature = signing_key
            .sign_prehash(digest)
            .map_err(|_| CoseSign1Error::Signature)?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&signature.to_bytes());
        Ok(out)
    }
}

/// Struct-based API for COSE_Sign1 encoding and ES256 signing.
pub struct CoseSign1<'a, C: CoseCrypto> {
    crypto: C,
    option_flags: Sign1Options,
    key_id: Option<&'a [u8]>,
    external_aad: &'a [u8],
}

impl<'a, C: CoseCrypto> CoseSign1<'a, C> {
    /// Creates a signer configured for ES256 using a raw 32-byte P-256 private key.
    pub fn new(crypto: C, option_flags: Sign1Options) -> Self {
        Self {
            crypto,
            option_flags,
            key_id: None,
            external_aad: &[],
        }
    }

    #[allow(dead_code)]
    /// Sets the COSE `kid` value for the unprotected header.
    pub const fn with_key_id(mut self, key_id: &'a [u8]) -> Self {
        self.key_id = Some(key_id);
        self
    }

    #[allow(dead_code)]
    /// Sets external AAD used in `Sig_structure`.
    pub const fn with_external_aad(mut self, external_aad: &'a [u8]) -> Self {
        self.external_aad = external_aad;
        self
    }

    /// Encodes a complete COSE_Sign1 using a caller-prepared encoded payload bstr.
    ///
    /// `payload_bstr` must be one CBOR bstr item containing the payload.
    pub fn encode_from_payload_bstr(
        &self,
        payload_bstr: &[u8],
        out: &mut [u8],
    ) -> Result<EncodedParameters, CoseSign1Error> {
        validate_payload_bstr(payload_bstr)?;

        let mut protected_headers = [0u8; 16];
        let mut protected_headers_enc = Encoder::new(Cursor::new(&mut protected_headers[..]));
        protected_headers_enc
            .map(1)
            .map_err(map_encode_error)?
            .u8(CoseHeaderLabels::Alg as u8)
            .map_err(map_encode_error)?
            .i32(COSE_ALGORITHM_ES256)
            .map_err(map_encode_error)?;
        let protected_headers_len = protected_headers_enc.writer().position();
        let protected_headers = &protected_headers[..protected_headers_len];

        let digest = hash_sig_structure(
            &self.crypto,
            protected_headers,
            self.external_aad,
            payload_bstr,
        )?;
        let signature_bytes = self.crypto.sign_es256_prehash(&digest)?;

        let mut sign1_enc = Encoder::new(Cursor::new(out));
        if !self.option_flags.omit_cbor_tag {
            sign1_enc
                .tag(Tag::new(CBOR_TAG_COSE_SIGN1))
                .map_err(map_encode_error)?;
        }

        sign1_enc
            .array(4)
            .map_err(map_encode_error)?
            .bytes(protected_headers)
            .map_err(map_encode_error)?;

        if self.key_id.is_some() {
            sign1_enc
                .map(1)
                .map_err(map_encode_error)?
                .u8(CoseHeaderLabels::Kid as u8)
                .map_err(map_encode_error)?
                .bytes(self.key_id.unwrap_or(&[]))
                .map_err(map_encode_error)?;
        } else {
            sign1_enc.map(0).map_err(map_encode_error)?;
        }

        if self.option_flags.detached_payload {
            sign1_enc.null().map_err(map_encode_error)?;
        } else {
            sign1_enc
                .writer_mut()
                .write_all(payload_bstr)
                .map_err(|_| CoseSign1Error::BufferTooSmall)?;
        }

        sign1_enc
            .bytes(&signature_bytes)
            .map_err(map_encode_error)?;

        Ok(EncodedParameters {
            encoded_len: sign1_enc.writer().position(),
            payload_is_detached: self.option_flags.detached_payload,
        })
    }
}

fn map_encode_error(err: minicbor::encode::Error<EndOfSlice>) -> CoseSign1Error {
    if err.as_write().is_some() {
        CoseSign1Error::BufferTooSmall
    } else {
        CoseSign1Error::CborEncoding
    }
}

fn validate_payload_bstr(encoded_payload_bstr: &[u8]) -> Result<(), CoseSign1Error> {
    let mut decoder = Decoder::new(encoded_payload_bstr);
    decoder
        .bytes()
        .map_err(|_| CoseSign1Error::InvalidPayload)?;
    if decoder.position() != encoded_payload_bstr.len() {
        return Err(CoseSign1Error::InvalidPayload);
    }
    Ok(())
}

fn hash_sig_structure(
    crypto: &impl CoseCrypto,
    protected_headers: &[u8],
    external_aad: &[u8],
    payload_bstr: &[u8],
) -> Result<[u8; 32], CoseSign1Error> {
    let mut hasher = crypto.hasher_sha256();

    hasher.update(&[0x84]);
    hash_cbor_text(&mut hasher, SIG_CONTEXT_STRING.as_bytes());
    hash_cbor_bstr(&mut hasher, protected_headers);
    hash_cbor_bstr(&mut hasher, external_aad);
    hasher.update(payload_bstr);

    Ok(hasher.finalize())
}

fn hash_cbor_text(hasher: &mut impl CoseHasher, value: &[u8]) {
    hash_cbor_major_len(hasher, 3, value.len());
    hasher.update(value);
}

fn hash_cbor_bstr(hasher: &mut impl CoseHasher, value: &[u8]) {
    hash_cbor_major_len(hasher, 2, value.len());
    hasher.update(value);
}

fn hash_cbor_major_len(hasher: &mut impl CoseHasher, major: u8, len: usize) {
    let mut header = [0u8; 9];
    let header_len = if len <= 23 {
        header[0] = (major << 5) | (len as u8);
        1
    } else if len <= 0xff {
        header[0] = (major << 5) | 24;
        header[1] = len as u8;
        2
    } else if len <= 0xffff {
        header[0] = (major << 5) | 25;
        header[1..3].copy_from_slice(&(len as u16).to_be_bytes());
        3
    } else if len <= 0xffff_ffff {
        header[0] = (major << 5) | 26;
        header[1..5].copy_from_slice(&(len as u32).to_be_bytes());
        5
    } else {
        header[0] = (major << 5) | 27;
        header[1..9].copy_from_slice(&(len as u64).to_be_bytes());
        9
    };
    hasher.update(&header[..header_len]);
}

/// Encodes a CBOR bstr from raw payload bytes.
///
/// This is useful when the payload bstr is prepared separately and then passed
/// to [`CoseSign1::encode_from_payload_bstr`].
pub fn encode_payload_bstr(payload: &[u8], out: &mut [u8]) -> Result<usize, CoseSign1Error> {
    let mut payload_bstr_enc = Encoder::new(Cursor::new(out));
    payload_bstr_enc.bytes(payload).map_err(map_encode_error)?;
    Ok(payload_bstr_enc.writer().position())
}

#[cfg(test)]
mod tests {
    use super::{
        CoseSign1, CoseSign1Error, RustCryptoBackend, Sign1Options, encode_payload_bstr,
        validate_payload_bstr, CBOR_TAG_COSE_SIGN1,
    };

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

    fn make_signer<'a>() -> CoseSign1<'a, RustCryptoBackend<'a>> {
        let backend = RustCryptoBackend { key: TEST_PRIVATE_KEY };
        CoseSign1::new(backend, Sign1Options::default())
    }

    fn encode_test_payload_bstr() -> ([u8; 32], usize) {
        let mut buf = [0u8; 32];
        let len = encode_payload_bstr(TEST_PAYLOAD, &mut buf).unwrap();
        (buf, len)
    }

    #[test]
    fn encodes_test_vector_from_payload_bstr() {
        let backend = RustCryptoBackend { key: TEST_PRIVATE_KEY };
        let signer = CoseSign1::new(backend, Sign1Options::default())
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
    fn encode_payload_bstr_buffer_too_small() {
        let mut buf = [0u8; 1]; // Too small for the header + payload
        let result = encode_payload_bstr(TEST_PAYLOAD, &mut buf);
        assert_eq!(result, Err(CoseSign1Error::BufferTooSmall));
    }

    #[test]
    fn validate_payload_bstr_rejects_empty_input() {
        assert_eq!(validate_payload_bstr(&[]), Err(CoseSign1Error::InvalidPayload));
    }

    #[test]
    fn validate_payload_bstr_rejects_non_bstr() {
        // 0x01 is CBOR unsigned integer 1, not a bstr
        assert_eq!(validate_payload_bstr(&[0x01]), Err(CoseSign1Error::InvalidPayload));
    }

    #[test]
    fn validate_payload_bstr_rejects_trailing_bytes() {
        // 0x40 is a valid empty bstr, but 0xFF is trailing
        assert_eq!(validate_payload_bstr(&[0x40, 0xFF]), Err(CoseSign1Error::InvalidPayload));
    }

    #[test]
    fn validate_payload_bstr_accepts_valid() {
        let mut buf = [0u8; 32];
        let len = encode_payload_bstr(TEST_PAYLOAD, &mut buf).unwrap();
        assert!(validate_payload_bstr(&buf[..len]).is_ok());
    }

    #[test]
    fn encode_without_cbor_tag() {
        let backend = RustCryptoBackend { key: TEST_PRIVATE_KEY };
        let opts = Sign1Options { omit_cbor_tag: true, detached_payload: false };
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
        let backend = RustCryptoBackend { key: TEST_PRIVATE_KEY };
        let opts = Sign1Options { omit_cbor_tag: false, detached_payload: true };
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
    fn sign1_options_default() {
        let opts = Sign1Options::default();
        assert!(!opts.omit_cbor_tag);
        assert!(!opts.detached_payload);
    }

    #[test]
    fn with_external_aad() {
        let backend = RustCryptoBackend { key: TEST_PRIVATE_KEY };
        let signer = CoseSign1::new(backend, Sign1Options::default())
            .with_external_aad(b"extra context");
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

    #[test]
    fn cbor_tag_value() {
        assert_eq!(CBOR_TAG_COSE_SIGN1, 18);
    }
}
