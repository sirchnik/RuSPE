use crate::types;

use crate::PsaApiCallInterface;

pub fn initial_attest_get_token<T: PsaApiCallInterface>(
    challenge: &[u8],
    token_buf: &mut [u8],
) -> Result<(), types::PsaStatus> {
    let in_vec = [types::PsaInVec {
        base: challenge.as_ptr(),
        len: challenge.len(),
    }];

    let mut out_vec = [types::PsaOutVec {
        base: token_buf.as_mut_ptr(),
        len: token_buf.len(),
    }];

    let status = T::psa_call(
        types::PsaHandle::AttestationService,
        types::VectorDescriptor::new(
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
        types::PsaInVec {
            base: &iov as *const types::TfmCryptoPackIovec as *const u8,
            len: core::mem::size_of::<types::TfmCryptoPackIovec>(),
        },
        types::PsaInVec {
            base: hash.as_ptr(),
            len: hash.len(),
        },
    ];

    let mut out_vec = [types::PsaOutVec {
        base: signature.as_mut_ptr(),
        len: signature.len(),
    }];

    let status = T::psa_call(
        types::PsaHandle::Crypto,
        types::VectorDescriptor::new(types::CryptoServiceType::SignHash as i16, 2, true, 1, true),
        &in_vec,
        &mut out_vec,
    );

    if status == 0 {
        Ok(out_vec[0].len)
    } else {
        Err(status)
    }
}
