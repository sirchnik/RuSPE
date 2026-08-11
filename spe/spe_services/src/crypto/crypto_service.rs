// SPDX-FileCopyrightText: Infineon Technologies AG
// SPDX-FileCopyrightText: 2018-2023, Arm Limited.
// SPDX-FileCopyrightText: 2026 The TrustedFirmware-M
// Contributors.
//
// SPDX-License-Identifier: MIT

#![cfg_attr(
    feature = "unsafe_mbedtls",
    allow(unsafe_code, reason = "mbedtls uses C-FFI")
)]

#[cfg(all(feature = "rustcrypto", feature = "unsafe_mbedtls"))]
compile_error!("Features 'rustcrypto' and 'unsafe_mbedtls' are mutually exclusive.");
#[cfg(not(any(feature = "rustcrypto", feature = "unsafe_mbedtls")))]
compile_error!("At least one of 'rustcrypto' or 'unsafe_mbedtls' features must be enabled.");

use psa_interface::types::{
    PSA_ALG_SHA_256, PsaAlgorithm, TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID,
    TFM_CRYPTO_HASH_COMPUTE_SID, TfmCryptoPackIovec,
};
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

    #[cfg(feature = "unsafe_mbedtls")]
    // Dummy RNG
    unsafe extern "C" fn dummy_rng(
        _data: *mut core::ffi::c_void,
        buf: *mut core::ffi::c_uchar,
        len: usize,
    ) -> core::ffi::c_int {
        // SAFETY: mbedtls FFI provides a valid buffer and length.
        unsafe {
            core::slice::from_raw_parts_mut(buf, len).fill(0x55);
        }
        0
    }

    #[inline(never)]
    fn sign_hash(&self, hash: &[u8], signature_buf: &mut [u8]) -> Result<usize, StatusCode> {
        #[cfg(feature = "unsafe_mbedtls")]
        return self.sign_hash_unsafe_mbedtls(hash, signature_buf);

        #[cfg(feature = "rustcrypto")]
        return self.sign_hash_rustcrypto(hash, signature_buf);
    }

    #[cfg(feature = "unsafe_mbedtls")]
    fn sign_hash_unsafe_mbedtls(
        &self,
        hash: &[u8],
        signature_buf: &mut [u8],
    ) -> Result<usize, StatusCode> {
        use mbedtls_rs::sys::{
            mbedtls_ecdsa_sign, mbedtls_ecp_group, mbedtls_ecp_group_free,
            mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1, mbedtls_ecp_group_init,
            mbedtls_ecp_group_load, mbedtls_mpi, mbedtls_mpi_free, mbedtls_mpi_init,
            mbedtls_mpi_read_binary, mbedtls_mpi_write_binary,
        };

        if hash.len() != SHA256_HASH_SIZE {
            return Err(StatusCode::InvalidArgument);
        }

        if signature_buf.len() < P256_SIGNATURE_SIZE {
            return Err(StatusCode::BufferTooSmall);
        }

        // SAFETY: mbedtls FFI calls for signing. Pointers are valid.
        unsafe {
            let mut grp: mbedtls_ecp_group = core::mem::zeroed();
            mbedtls_ecp_group_init(&raw mut grp);
            mbedtls_ecp_group_load(&raw mut grp, mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);

            let mut d: mbedtls_mpi = core::mem::zeroed();
            mbedtls_mpi_init(&raw mut d);
            mbedtls_mpi_read_binary(&raw mut d, self.signing_key.as_ptr(), 32);

            let mut r: mbedtls_mpi = core::mem::zeroed();
            let mut s: mbedtls_mpi = core::mem::zeroed();
            mbedtls_mpi_init(&raw mut r);
            mbedtls_mpi_init(&raw mut s);

            let ret = mbedtls_ecdsa_sign(
                &raw mut grp,
                &raw mut r,
                &raw mut s,
                &raw mut d,
                hash.as_ptr(),
                hash.len(),
                Some(Self::dummy_rng),
                core::ptr::null_mut(),
            );

            if ret != 0 {
                return Err(StatusCode::GenericError);
            }

            mbedtls_mpi_write_binary(&raw const r, signature_buf[0..32].as_mut_ptr(), 32);
            mbedtls_mpi_write_binary(&raw const s, signature_buf[32..64].as_mut_ptr(), 32);

            mbedtls_mpi_free(&raw mut r);
            mbedtls_mpi_free(&raw mut s);
            mbedtls_mpi_free(&raw mut d);
            mbedtls_ecp_group_free(&raw mut grp);
        }

        Ok(P256_SIGNATURE_SIZE)
    }

    #[cfg(feature = "rustcrypto")]
    fn sign_hash_rustcrypto(
        &self,
        hash: &[u8],
        signature_buf: &mut [u8],
    ) -> Result<usize, StatusCode> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::{Signature, SigningKey};

        if hash.len() != SHA256_HASH_SIZE {
            return Err(StatusCode::InvalidArgument);
        }

        if signature_buf.len() < P256_SIGNATURE_SIZE {
            return Err(StatusCode::BufferTooSmall);
        }

        let signing_key = SigningKey::from_bytes(self.signing_key.as_slice().into())
            .map_err(|_| StatusCode::InvalidArgument)?;

        let signature: Signature = signing_key
            .sign_prehash(hash)
            .map_err(|_| StatusCode::GenericError)?;

        signature_buf[..P256_SIGNATURE_SIZE].copy_from_slice(signature.to_bytes().as_ref());

        Ok(P256_SIGNATURE_SIZE)
    }

    #[inline(never)]
    fn compute_hash(
        alg: PsaAlgorithm,
        input: &[u8],
        hash_buf: &mut [u8],
    ) -> Result<usize, StatusCode> {
        #[cfg(feature = "unsafe_mbedtls")]
        return Self::compute_hash_unsafe_mbedtls(alg, input, hash_buf);

        #[cfg(feature = "rustcrypto")]
        return Self::compute_hash_rustcrypto(alg, input, hash_buf);
    }

    #[cfg(feature = "unsafe_mbedtls")]
    fn compute_hash_unsafe_mbedtls(
        alg: PsaAlgorithm,
        input: &[u8],
        hash_buf: &mut [u8],
    ) -> Result<usize, StatusCode> {
        use mbedtls_rs::sys::{
            mbedtls_md_context_t, mbedtls_md_finish, mbedtls_md_free, mbedtls_md_info_from_type,
            mbedtls_md_init, mbedtls_md_setup, mbedtls_md_starts,
            mbedtls_md_type_t_MBEDTLS_MD_SHA256, mbedtls_md_update,
        };

        if alg != PSA_ALG_SHA_256 {
            return Err(StatusCode::NotSupported);
        }

        if hash_buf.len() < SHA256_HASH_SIZE {
            return Err(StatusCode::BufferTooSmall);
        }

        // SAFETY: Calling mbedtls FFI. Pointers are valid.
        unsafe {
            let mut ctx: mbedtls_md_context_t = core::mem::zeroed();
            mbedtls_md_init(&raw mut ctx);
            let info = mbedtls_md_info_from_type(mbedtls_md_type_t_MBEDTLS_MD_SHA256);
            mbedtls_md_setup(&raw mut ctx, info, 0);
            mbedtls_md_starts(&raw mut ctx);
            mbedtls_md_update(&raw mut ctx, input.as_ptr(), input.len());
            mbedtls_md_finish(&raw mut ctx, hash_buf.as_mut_ptr());
            mbedtls_md_free(&raw mut ctx);
        }

        Ok(SHA256_HASH_SIZE)
    }

    #[cfg(feature = "rustcrypto")]
    fn compute_hash_rustcrypto(
        alg: PsaAlgorithm,
        input: &[u8],
        hash_buf: &mut [u8],
    ) -> Result<usize, StatusCode> {
        use sha2::{Digest, Sha256};

        if alg != PSA_ALG_SHA_256 {
            return Err(StatusCode::NotSupported);
        }

        if hash_buf.len() < SHA256_HASH_SIZE {
            return Err(StatusCode::BufferTooSmall);
        }

        let hash = Sha256::digest(input);
        hash_buf[..SHA256_HASH_SIZE].copy_from_slice(hash.as_ref());

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
    use sha2::{Digest, Sha256};

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
