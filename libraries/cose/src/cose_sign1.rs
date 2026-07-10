// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Minimal COSE_Sign1 parameter encoding support.
//!
//! This module supports only ECDSA with SHA-256 (COSE alg `ES256`, `-7`).

use minicbor::data::Tag;
use minicbor::encode::Write;
use minicbor::encode::write::{Cursor, EndOfSlice};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
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

impl<'a> RustCryptoBackend<'a> {
    pub fn new(key: &'a [u8]) -> Self {
        Self { key }
    }
}

#[repr(align(32))]
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
    /// Creates a signer configured for ES256 using a raw 32-byte P-256 private
    /// key.
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

    /// Encodes a complete COSE_Sign1 using a caller-prepared encoded payload
    /// bstr.
    ///
    /// `payload_bstr` must be one CBOR bstr item containing the payload.
    pub fn encode_from_payload_bstr(
        &self,
        payload_bstr: &[u8],
        out: &mut [u8],
    ) -> Result<EncodedParameters, CoseSign1Error> {
        validate_payload_bstr(payload_bstr)?;

        let (protected_headers_buf, protected_headers_len) = encode_protected_headers()?;
        let protected_headers = &protected_headers_buf[..protected_headers_len];

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

        if let Some(kid) = self.key_id {
            sign1_enc
                .map(1)
                .map_err(map_encode_error)?
                .u8(CoseHeaderLabels::Kid as u8)
                .map_err(map_encode_error)?
                .bytes(kid)
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

fn encode_protected_headers() -> Result<([u8; 16], usize), CoseSign1Error> {
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
    Ok((protected_headers, protected_headers_len))
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
    let header_len = encode_cbor_major_len_header(major, len, &mut header);
    hasher.update(&header[..header_len]);
}

fn encode_cbor_major_len_header(major: u8, len: usize, header: &mut [u8; 9]) -> usize {
    if len <= 23 {
        header[0] = (major << 5) | (len as u8);
        1
    } else if len <= 0xff {
        header[0] = (major << 5) | 0x18;
        header[1] = len as u8;
        2
    } else if len <= 0xffff {
        header[0] = (major << 5) | 0x19;
        header[1..3].copy_from_slice(&(len as u16).to_be_bytes());
        3
    } else if len <= 0xffff_ffff {
        header[0] = (major << 5) | 0x1a;
        header[1..5].copy_from_slice(&(len as u32).to_be_bytes());
        5
    } else {
        header[0] = (major << 5) | 0x1b;
        header[1..9].copy_from_slice(&(len as u64).to_be_bytes());
        9
    }
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

/// Encodes a CBOR bstr in-place from raw payload bytes.
///
/// The payload must start at the beginning of `out` and will be shifted forward
/// to make room for the bstr header.
pub fn encode_payload_bstr_in_place(
    payload_len: usize,
    out: &mut [u8],
) -> Result<usize, CoseSign1Error> {
    let mut header = [0u8; 9];
    let header_len = encode_cbor_major_len_header(2, payload_len, &mut header);
    let total_len = payload_len
        .checked_add(header_len)
        .ok_or(CoseSign1Error::BufferTooSmall)?;

    if total_len > out.len() {
        return Err(CoseSign1Error::BufferTooSmall);
    }

    out.copy_within(0..payload_len, header_len);
    out[..header_len].copy_from_slice(&header[..header_len]);
    Ok(total_len)
}

#[cfg(test)]
#[path = "cose_sign1_test.rs"]
mod tests;
