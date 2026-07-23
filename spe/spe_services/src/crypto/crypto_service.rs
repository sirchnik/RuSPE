// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use psa_interface::types::{TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID, TfmCryptoPackIovec};
use spe::StatusCode;
use spe::service::Service;
use spe::spm_api::{PsaMsg, SpmApi};

/// P-256 ECDSA signature size in bytes (r || s, 32 + 32).
const P256_SIGNATURE_SIZE: usize = 64;
/// SHA-256 digest length in bytes.
const SHA256_HASH_SIZE: usize = 32;

pub struct CryptoService {
    signing_key: [u8; 32],
}

impl CryptoService {
    pub const VERSION: u32 = 1;

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

impl<A: SpmApi> Service<A> for CryptoService {
    fn call(&self, msg: PsaMsg, api: &A) -> Result<(), StatusCode> {
        // TF-M layout: invec[0] = TfmCryptoPackIovec, invec[1] = hash,
        //              outvec[0] = signature buffer.
        api.access_invec(msg.handle, 0, |buf| -> Result<(), StatusCode> {
            let iov: &TfmCryptoPackIovec =
                bytemuck::try_from_bytes(buf).map_err(|_| StatusCode::ProgrammerError)?;

            if iov.function_id != TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID {
                return Err(StatusCode::NotSupported);
            }
            Ok(())
        })??;

        api.access_invec_outvec(msg.handle, 1, 0, |hash, sig_buf| {
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
        })??;
        Ok(())
    }

    fn init(&mut self, _api: &A) -> Result<(), StatusCode> {
        Ok(())
    }

    fn deinit(&mut self, _api: &A) -> Result<(), StatusCode> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use psa_interface::status::StatusCode;

    use super::*;

    #[test]
    fn test_sign_hash_success() {
        let mut key = [0u8; 32];
        key[31] = 1; // A valid scalar
        let service = CryptoService::new(key);
        let hash = [0u8; 32];
        let mut sig_buf = [0u8; 64];

        let res = service.sign_hash(&hash, &mut sig_buf);
        assert_eq!(res, Ok(64));
    }

    #[test]
    fn test_sign_hash_invalid_hash_len() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let service = CryptoService::new(key);
        let hash = [0u8; 31];
        let mut sig_buf = [0u8; 64];

        let res = service.sign_hash(&hash, &mut sig_buf);
        assert_eq!(res, Err(StatusCode::InvalidArgument));
    }

    #[test]
    fn test_sign_hash_buffer_too_small() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let service = CryptoService::new(key);
        let hash = [0u8; 32];
        let mut sig_buf = [0u8; 63];

        let res = service.sign_hash(&hash, &mut sig_buf);
        assert_eq!(res, Err(StatusCode::BufferTooSmall));
    }
}
