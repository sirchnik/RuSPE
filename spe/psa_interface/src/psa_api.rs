use crate::types;

use crate::PsaApiCallInterface;

pub fn initial_attest_get_token<T: PsaApiCallInterface>(
    challenge: &[u8],
    token_buf: &mut [u8],
) -> Result<(), types::PsaStatus> {
    let in_vec = [types::FFInVec {
        base: challenge.as_ptr(),
        len: challenge.len(),
    }];

    let mut out_vec = [types::FFOutVec {
        base: token_buf.as_mut_ptr(),
        len: token_buf.len(),
    }];

    let status = T::psa_call(
        types::ServiceHandle::AttestationService,
        types::CtrlParam::new(
            types::AttestationServiceType::GetToken as i16,
            1,
            true,
            1,
            true,
        ),
        &in_vec,
        &mut out_vec,
    );

    if status == 0 { Ok(()) } else { Err(status) }
}

/// PSA Crypto `psa_sign_hash` — sign a pre-computed hash.
///
/// Matches the TF-M iovec layout:
///   invec\[0\] = `TfmCryptoPackIovec` (function_id, key_id, alg)
///   invec\[1\] = hash
///   outvec\[0\] = signature buffer
///
/// On success, returns the number of bytes written to `signature`.
pub fn psa_sign_hash<T: PsaApiCallInterface>(
    key: types::PsaKeyId,
    alg: types::PsaAlgorithm,
    hash: &[u8],
    signature: &mut [u8],
) -> Result<usize, types::PsaStatus> {
    let iov = types::TfmCryptoPackIovec::for_sign_hash(key, alg);

    let in_vec = [
        types::FFInVec {
            base: core::ptr::from_ref::<types::TfmCryptoPackIovec>(&iov).cast::<u8>(),
            len: core::mem::size_of::<types::TfmCryptoPackIovec>(),
        },
        types::FFInVec {
            base: hash.as_ptr(),
            len: hash.len(),
        },
    ];

    let mut out_vec = [types::FFOutVec {
        base: signature.as_mut_ptr(),
        len: signature.len(),
    }];

    let status = T::psa_call(
        types::ServiceHandle::Crypto,
        types::CtrlParam::new(types::CryptoServiceType::SignHash as i16, 2, true, 1, true),
        &in_vec,
        &mut out_vec,
    );

    if status == 0 {
        Ok(out_vec[0].len)
    } else {
        Err(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicIsize, Ordering};

    static MOCK_RETURN_STATUS: AtomicIsize = AtomicIsize::new(0);
    static MOCK_OUT_LEN: AtomicIsize = AtomicIsize::new(0);

    struct MockPsaClient;

    impl PsaApiCallInterface for MockPsaClient {
        fn psa_framework_version() -> u32 {
            0x0102
        }

        fn psa_version(_service_id: u32) -> u32 {
            1
        }

        fn psa_call(
            _handle: types::ServiceHandle,
            _ctrl_param: types::CtrlParam,
            _in_vec: &[types::FFInVec],
            out_vec: &mut [types::FFOutVec],
        ) -> types::PsaStatus {
            let status = MOCK_RETURN_STATUS.load(Ordering::Relaxed);
            if status == 0 {
                let out_len = MOCK_OUT_LEN.load(Ordering::Relaxed) as usize;
                if !out_vec.is_empty() {
                    out_vec[0].len = out_len;
                }
            }
            status
        }
    }

    #[test]
    fn initial_attest_get_token_success() {
        MOCK_RETURN_STATUS.store(0, Ordering::Relaxed);
        let challenge = [0u8; 32];
        let mut token = [0u8; 256];
        let result = initial_attest_get_token::<MockPsaClient>(&challenge, &mut token);
        assert!(result.is_ok());
    }

    #[test]
    fn initial_attest_get_token_error() {
        MOCK_RETURN_STATUS.store(-132, Ordering::Relaxed); // GenericError
        let challenge = [0u8; 32];
        let mut token = [0u8; 256];
        let result = initial_attest_get_token::<MockPsaClient>(&challenge, &mut token);
        assert_eq!(result, Err(-132));
    }

    #[test]
    fn psa_sign_hash_success() {
        MOCK_RETURN_STATUS.store(0, Ordering::Relaxed);
        MOCK_OUT_LEN.store(64, Ordering::Relaxed);
        let hash = [0u8; 32];
        let mut sig = [0u8; 64];
        let result =
            psa_sign_hash::<MockPsaClient>(1, types::PSA_ALG_ECDSA_SHA256, &hash, &mut sig);
        assert_eq!(result, Ok(64));
    }

    #[test]
    fn psa_sign_hash_error() {
        MOCK_RETURN_STATUS.store(-134, Ordering::Relaxed); // NotSupported
        let hash = [0u8; 32];
        let mut sig = [0u8; 64];
        let result =
            psa_sign_hash::<MockPsaClient>(1, types::PSA_ALG_ECDSA_SHA256, &hash, &mut sig);
        assert_eq!(result, Err(-134));
    }
}
