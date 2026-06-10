// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use psa_interface::types::{TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID, TfmCryptoPackIovec};
use spe::{
    StatusCode,
    psa::{psa_api, psa_call::PsaMsg},
    service::{Info, Service},
};

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
}

impl Service for CryptoService {
    fn info(&self) -> Info {
        Info { version: 1 }
    }

    fn call(&self, msg: PsaMsg) -> Result<(), psa_interface::status::StatusCode> {
        // TF-M layout: invec[0] = TfmCryptoPackIovec, invec[1] = hash,
        //              outvec[0] = signature buffer.
        psa_api::psa_map_invec(msg.handle, 0, |buf| -> Result<(), StatusCode> {
            let iov: &TfmCryptoPackIovec =
                bytemuck::try_from_bytes(buf).map_err(|_| StatusCode::ProgrammerError)?;

            if iov.function_id != TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID {
                return Err(StatusCode::NotSupported);
            }
            Ok(())
        })?;

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
