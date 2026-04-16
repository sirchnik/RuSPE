// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

//! Minimal COSE_Sign1 parameter encoding support.
//!
//! This migrates the behavior of:
//! - `t_cose_sign1_sign_init`
//! - `t_cose_sign1_set_signing_key`
//! - `t_cose_sign1_encode_parameters`
//!
//! The cryptographic implementation is configurable via [`CoseCryptoBackend`].

use minicbor::{
    Encoder,
    data::Tag,
    encode::write::{Cursor, EndOfSlice},
};

/// COSE header label: algorithm.
pub const COSE_HEADER_PARAM_ALG: u8 = 1;
/// COSE header label: content type.
pub const COSE_HEADER_PARAM_CONTENT_TYPE: u8 = 3;
/// COSE header label: key id.
pub const COSE_HEADER_PARAM_KID: u8 = 4;
/// CBOR tag for COSE_Sign1.
pub const CBOR_TAG_COSE_SIGN1: u64 = 18;

/// COSE algorithm ID for ECDSA + SHA-256.
pub const COSE_ALGORITHM_ES256: i32 = -7;
/// COSE algorithm ID for EDDSA.
pub const COSE_ALGORITHM_EDDSA: i32 = -8;
/// COSE algorithm ID for ECDSA + SHA-384.
pub const COSE_ALGORITHM_ES384: i32 = -35;
/// COSE algorithm ID for ECDSA + SHA-512.
pub const COSE_ALGORITHM_ES512: i32 = -36;
/// COSE algorithm ID for RSASSA-PSS + SHA-256.
pub const COSE_ALGORITHM_PS256: i32 = -37;
/// COSE algorithm ID for RSASSA-PSS + SHA-384.
pub const COSE_ALGORITHM_PS384: i32 = -38;
/// COSE algorithm ID for RSASSA-PSS + SHA-512.
pub const COSE_ALGORITHM_PS512: i32 = -39;

const SHORT_CIRCUIT_KID: [u8; 32] = [
    0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70, 0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
    0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6, 0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6,
];

/// Errors returned by COSE Sign1 parameter setup/encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoseSign1Error {
    /// The selected signing algorithm is not supported by the backend.
    UnsupportedSigningAlg,
    /// Both integer and text content type were set.
    DuplicateParameter,
    /// Output buffer is too small.
    BufferTooSmall,
    /// Generic encoding error.
    CborEncoding,
}

/// Option flags corresponding to t_cose Sign1 behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sign1Options {
    /// Do not emit CBOR tag 18.
    pub omit_cbor_tag: bool,
    /// Enable short-circuit signing mode behavior for `kid` handling.
    pub short_circuit_signature: bool,
}

/// Result of encoding COSE_Sign1 parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedParameters {
    /// Number of bytes encoded into the output buffer.
    pub encoded_len: usize,
    /// Whether detached payload mode was requested by the caller.
    pub payload_is_detached: bool,
}

/// Backend abstraction for configurable crypto implementations.
pub trait CoseCryptoBackend {
    /// Signing key type used by this backend.
    type SigningKey;

    /// Returns true if the backend supports the COSE signing algorithm.
    fn is_signing_algorithm_supported(&self, cose_algorithm_id: i32) -> bool;
}

/// Default algorithm-support backend matching t_cose supported IDs.
#[derive(Clone, Copy, Debug, Default)]
pub struct ToseLikeAlgorithmSupport;

impl CoseCryptoBackend for ToseLikeAlgorithmSupport {
    type SigningKey = ();

    fn is_signing_algorithm_supported(&self, cose_algorithm_id: i32) -> bool {
        matches!(
            cose_algorithm_id,
            COSE_ALGORITHM_ES256
                | COSE_ALGORITHM_ES384
                | COSE_ALGORITHM_ES512
                | COSE_ALGORITHM_PS256
                | COSE_ALGORITHM_PS384
                | COSE_ALGORITHM_PS512
                | COSE_ALGORITHM_EDDSA
        )
    }
    sign
}

/// Struct-based API for COSE_Sign1 setup and parameter encoding.
pub struct CoseSign1<'a, B: CoseCryptoBackend> {
    crypto: B,
    cose_algorithm_id: i32,
    option_flags: Sign1Options,
    signing_key: Option<B::SigningKey>,
    kid: Option<&'a [u8]>,
    content_type_uint: Option<u64>,
    content_type_tstr: Option<&'a str>,
    protected_parameters: [u8; 8],
    protected_parameters_len: usize,
}

impl<'a, B: CoseCryptoBackend> CoseSign1<'a, B> {
    /// Migrated equivalent of `t_cose_sign1_sign_init`.
    pub const fn new(crypto: B, cose_algorithm_id: i32, option_flags: Sign1Options) -> Self {
        Self {
            crypto,
            cose_algorithm_id,
            option_flags,
            signing_key: None,
            kid: None,
            content_type_uint: None,
            content_type_tstr: None,
            protected_parameters: [0; 8],
            protected_parameters_len: 0,
        }
    }

    /// Migrated equivalent of `t_cose_sign1_encode_parameters` behavior.
    ///
    /// Encodes:
    /// - optional COSE_Sign1 tag,
    /// - start of 4-entry COSE_Sign1 array,
    /// - protected parameters,
    /// - unprotected parameters.
    ///
    /// Payload and signature array entries are intentionally left to the caller.
    pub fn t_cose_sign1_encode_parameters(
        &mut self,
        payload_is_detached: bool,
        out: &mut [u8],
    ) -> Result<EncodedParameters, CoseSign1Error> {
        if !self
            .crypto
            .is_signing_algorithm_supported(self.cose_algorithm_id)
        {
            return Err(CoseSign1Error::UnsupportedSigningAlg);
        }

        if self.content_type_uint.is_some() && self.content_type_tstr.is_some() {
            return Err(CoseSign1Error::DuplicateParameter);
        }

        let mut protected_scratch = [0u8; 8];
        let protected_capacity = protected_scratch.len();
        let mut protected_remaining = protected_scratch.as_mut_slice();
        {
            let mut protected_enc = Encoder::new(&mut protected_remaining);
            protected_enc
                .map(1)
                .map_err(map_encode_error)?
                .u8(COSE_HEADER_PARAM_ALG)
                .map_err(map_encode_error)?
                .i32(self.cose_algorithm_id)
                .map_err(map_encode_error)?;
        }

        let protected_len = protected_capacity - protected_remaining.len();
        self.protected_parameters[..protected_len]
            .copy_from_slice(&protected_scratch[..protected_len]);
        self.protected_parameters_len = protected_len;

        let resolved_kid = if self.option_flags.short_circuit_signature {
            match self.kid {
                Some(k) if !k.is_empty() => Some(k),
                _ => Some(SHORT_CIRCUIT_KID.as_slice()),
            }
        } else {
            self.kid.filter(|k| !k.is_empty())
        };

        let mut map_pairs = 0u64;
        if resolved_kid.is_some() {
            map_pairs += 1;
        }
        if self.content_type_uint.is_some() || self.content_type_tstr.is_some() {
            map_pairs += 1;
        }

        let mut cursor = Cursor::new(out);
        {
            let mut enc = Encoder::new(&mut cursor);
            if !self.option_flags.omit_cbor_tag {
                enc.tag(Tag::new(CBOR_TAG_COSE_SIGN1))
                    .map_err(map_encode_error)?;
            }

            enc.array(4)
                .map_err(map_encode_error)?
                .bytes(&protected_scratch[..protected_len])
                .map_err(map_encode_error)?
                .map(map_pairs)
                .map_err(map_encode_error)?;

            if let Some(kid) = resolved_kid {
                enc.u8(COSE_HEADER_PARAM_KID)
                    .map_err(map_encode_error)?
                    .bytes(kid)
                    .map_err(map_encode_error)?;
            }

            if let Some(content_type_uint) = self.content_type_uint {
                enc.u8(COSE_HEADER_PARAM_CONTENT_TYPE)
                    .map_err(map_encode_error)?
                    .u64(content_type_uint)
                    .map_err(map_encode_error)?;
            } else if let Some(content_type_tstr) = self.content_type_tstr {
                enc.u8(COSE_HEADER_PARAM_CONTENT_TYPE)
                    .map_err(map_encode_error)?
                    .str(content_type_tstr)
                    .map_err(map_encode_error)?;
            }
        }

        Ok(EncodedParameters {
            encoded_len: cursor.position(),
            payload_is_detached,
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
