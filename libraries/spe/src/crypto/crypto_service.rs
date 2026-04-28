// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

use crate::{
    StatusCode,
    psa::{psa_api, psa_call::PsaMsg},
    service::{Info, Service},
};
use p256::ecdsa::{SigningKey, Signature, signature::hazmat::PrehashSigner};
use psa_interface;

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

        let key = SigningKey::from_slice(&self.signing_key)
            .map_err(|_| StatusCode::GenericError)?;

        let hash_array: &[u8; 32] = hash.try_into().map_err(|_| StatusCode::InvalidArgument)?;

        let sig: Signature = key
            .sign_prehash(hash_array)
            .map_err(|_| StatusCode::GenericError)?;

        signature_buf[..P256_SIGNATURE_SIZE].copy_from_slice(&sig.to_bytes());
        Ok(P256_SIGNATURE_SIZE)
    }
}

impl Service for CryptoService {
    fn info(&self) -> Info {
        Info { version: 1 }
    }

    fn call(&self, msg: PsaMsg) -> Result<(), psa_interface::StatusCode> {
        if msg.msg_type == psa_interface::CryptoServiceType::SignHash as i32 {
            psa_api::psa_map_invec_outvec(msg.handle, 0, 0, |hash, sig_buf| {
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
        } else {
            Err(psa_interface::StatusCode::NotSupported)
        }
    }

    fn init(&mut self) -> Result<(), psa_interface::StatusCode> {
        Ok(())
    }

    fn deinit(&mut self) -> Result<(), psa_interface::StatusCode> {
        Ok(())
    }
}
