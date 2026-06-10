// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

use crate::{
    StatusCode,
    psa::{psa_api, psa_call::PsaMsg},
    service::{Info, Service},
};
use core::mem::size_of;
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use psa_interface::types::{TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID, TfmCryptoPackIovec};

/// P-256 ECDSA signature size in bytes (r ‖ s, 32 + 32).
const P256_SIGNATURE_SIZE: usize = 64;
/// SHA-256 digest length in bytes.
const SHA256_HASH_SIZE: usize = 32;

pub struct CryptoService {
    signing_key: [u8; 32],
}

impl CryptoService {
    pub const fn new(signing_key: [u8; 32]) -> Self {
        Self { signing_key }
    }

    fn sign_hash(&self, hash: &[u8], signature_buf: &mut [u8]) -> Result<usize, StatusCode> {
        if hash.len() != SHA256_HASH_SIZE {
            return Err(StatusCode::InvalidArgument);
        }

        if signature_buf.len() < P256_SIGNATURE_SIZE {
            return Err(StatusCode::BufferTooSmall);
        }

        let key =
            SigningKey::from_slice(&self.signing_key).map_err(|_| StatusCode::GenericError)?;

        let sig: Signature = key
            .sign_prehash(hash)
            .map_err(|_| StatusCode::GenericError)?;

        signature_buf[..P256_SIGNATURE_SIZE].copy_from_slice(&sig.to_bytes());
        Ok(P256_SIGNATURE_SIZE)
    }

    /// Parse a `TfmCryptoPackIovec` from raw invec bytes.
    fn parse_pack_iovec(buf: &[u8]) -> Result<TfmCryptoPackIovec, StatusCode> {
        if buf.len() != size_of::<TfmCryptoPackIovec>() {
            return Err(StatusCode::ProgrammerError);
        }
        let mut iov = TfmCryptoPackIovec::for_sign_hash(0, 0);
        let dst = &mut iov as *mut TfmCryptoPackIovec as *mut u8;
        for (i, &b) in buf.iter().enumerate() {
            // `dst` points to stack memory of exactly size_of::<TfmCryptoPackIovec>().
            // `i` is bounded by `buf.len()` which we checked equals that size.
            //
            // # Safety:
            // Writing to our own stack-allocated, correctly-sized struct.
            unsafe { dst.add(i).write(b) };
        }
        Ok(iov)
    }
}

impl Service for CryptoService {
    fn info(&self) -> Info {
        Info { version: 1 }
    }

    fn call(&self, msg: PsaMsg) -> Result<(), psa_interface::status::StatusCode> {
        // TF-M layout: invec[0] = TfmCryptoPackIovec, invec[1] = hash,
        //              outvec[0] = signature buffer.
        let iov =
            psa_api::psa_map_invec(msg.handle, 0, |iov_bytes| Self::parse_pack_iovec(iov_bytes))?;

        if iov.function_id != TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID {
            return Err(psa_interface::status::StatusCode::NotSupported);
        }

        psa_api::psa_map_invec_outvec(msg.handle, 1, 0, |hash, sig_buf| {
            let mut written_len = 0;
            let result = (|| -> Result<(), StatusCode> {
                written_len = self.sign_hash(hash, sig_buf)?;
                Ok(())
            })();

            if result.is_err() {
                sig_buf[..written_len].fill(0);
                written_len = 0;
            }

            (result, written_len)
        })
    }

    fn init(&mut self) -> Result<(), psa_interface::status::StatusCode> {
        Ok(())
    }

    fn deinit(&mut self) -> Result<(), psa_interface::status::StatusCode> {
        Ok(())
    }
}
