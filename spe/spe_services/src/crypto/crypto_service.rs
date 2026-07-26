// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use psa_interface::types::{
    PSA_ALG_SHA_256, PsaAlgorithm, TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID,
    TFM_CRYPTO_HASH_COMPUTE_SID, TfmCryptoPackIovec,
};
use sha2::{Digest, Sha256};
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

    fn compute_hash(
        alg: PsaAlgorithm,
        input: &[u8],
        hash_buf: &mut [u8],
    ) -> Result<usize, StatusCode> {
        if alg != PSA_ALG_SHA_256 {
            return Err(StatusCode::NotSupported);
        }

        if hash_buf.len() < SHA256_HASH_SIZE {
            return Err(StatusCode::BufferTooSmall);
        }

        let digest = Sha256::digest(input);
        hash_buf[..SHA256_HASH_SIZE].copy_from_slice(&digest);
        Ok(SHA256_HASH_SIZE)
    }
}

impl<A: SpmApi> Service<A> for CryptoService {
    fn call(&self, msg: PsaMsg, api: &A) -> Result<(), StatusCode> {
        // TF-M layout: invec[0] = TfmCryptoPackIovec, invec[1] = input/hash,
        //              outvec[0] = output buffer (signature or hash).
        let iov: TfmCryptoPackIovec = api.access_invec(
            msg.handle,
            0,
            |buf| -> Result<TfmCryptoPackIovec, StatusCode> {
                bytemuck::try_from_bytes(buf)
                    .copied()
                    .map_err(|_| StatusCode::ProgrammerError)
            },
        )??;

        match iov.function_id {
            TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID => {
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
            TFM_CRYPTO_HASH_COMPUTE_SID => {
                api.access_invec_outvec(msg.handle, 1, 0, |input, hash_buf| {
                    let mut written_len = 0;
                    let result = (|| -> Result<(), StatusCode> {
                        written_len = Self::compute_hash(iov.alg, input, hash_buf)?;
                        Ok(())
                    })();

                    if result.is_err() {
                        hash_buf[..written_len].fill(0);
                        written_len = 0;
                    }

                    (result, written_len)
                })??;
                Ok(())
            }
            _ => Err(StatusCode::NotSupported),
        }
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

    #[test]
    fn test_compute_hash_success() {
        let input = b"hello world";
        let mut hash_buf = [0u8; 32];

        let res = CryptoService::compute_hash(PSA_ALG_SHA_256, input, &mut hash_buf);
        assert_eq!(res, Ok(32));

        let expected_hash = Sha256::digest(input);
        assert_eq!(hash_buf, *expected_hash);
    }

    #[test]
    fn test_compute_hash_invalid_alg() {
        let input = b"hello world";
        let mut hash_buf = [0u8; 32];

        let res = CryptoService::compute_hash(0x1234, input, &mut hash_buf);
        assert_eq!(res, Err(StatusCode::NotSupported));
    }

    #[test]
    fn test_compute_hash_buffer_too_small() {
        let input = b"hello world";
        let mut hash_buf = [0u8; 31];

        let res = CryptoService::compute_hash(PSA_ALG_SHA_256, input, &mut hash_buf);
        assert_eq!(res, Err(StatusCode::BufferTooSmall));
    }
}
