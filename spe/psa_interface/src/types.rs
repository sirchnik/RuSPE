// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use bytemuck::{Pod, Zeroable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum ServiceHandle {
    InternalTrustedStorageService = 0x40000102,
    Crypto = 0x40000100,
    AttestationService = 0x40000103,
}

impl core::convert::TryFrom<i32> for ServiceHandle {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            v if v == Self::Crypto as i32 => Ok(Self::Crypto),
            v if v == Self::InternalTrustedStorageService as i32 => {
                Ok(Self::InternalTrustedStorageService)
            }
            v if v == Self::AttestationService as i32 => Ok(Self::AttestationService),
            _ => Err(()),
        }
    }
}

const _PSA_FF_1_0: u32 = 0x0100;
const _PSA_FF_1_1: u32 = 0x0101;
pub const PSA_FRAMEWORK_VERSION: u32 = 0x0100;

#[repr(C)]
pub enum AttestationServiceType {
    GetToken = 1001,
    GetTokenSize = 1002,
}

#[repr(C)]
pub enum CryptoServiceType {
    SignHash = 1,
}

/// FFI status integer used at the SPE/NSPE veneer boundary.
pub type PsaStatus = isize;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FFInVec {
    pub base: *const u8,
    pub len: usize,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FFOutVec {
    pub base: *mut u8,
    pub len: usize,
}

/// Control parameter for PSA IPC calls.
///
///  31           30-28   27    26-24  23-20   19     18-16   15-0
/// +------------+-----+------+-------+-----+-------+-------+------+
/// | NS vector  |     | NS   | invec |     | NS    | outvec| type |
/// | descriptor | Res | invec| number| Res | outvec| number|      |
/// +------------+-----+------+-------+-----+-------+-------+------+
///
/// Res: Reserved.
///
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CtrlParam(u32);

impl CtrlParam {
    pub const NS_VEC_DESC_BIT: u32 = 0x8000_0000;

    /// Creates a new descriptor from components, handling the masks and offsets.
    pub fn new(r#type: i16, in_len: u8, in_ns: bool, out_len: u8, out_ns: bool) -> Self {
        let mut val = (r#type as u16 as u32) & 0xFFFF;
        val |= ((in_len as u32) << 24) & 0x0700_0000; // IN_LEN_MASK
        val |= ((out_len as u32) << 16) & 0x0007_0000; // OUT_LEN_MASK
        if in_ns {
            val |= 0x0800_0000; // IN_NS_MASK
        }
        if out_ns {
            val |= 0x0008_0000; // OUT_NS_MASK
        }
        Self(val)
    }

    pub fn unpack_type(&self) -> i32 {
        (self.0 as u16 as i16) as i32
    }

    /// Port of PARAM_HAS_IOVEC
    /// Checks if any bits outside the type mask are set.
    pub fn has_iovec(&self) -> bool {
        // Equivalent to (ctrl_param) != (uint32_t)PARAM_UNPACK_TYPE(ctrl_param)
        (self.0 & !0xFFFF) != 0
    }

    pub fn set_ns_vec(&mut self) {
        self.0 |= Self::NS_VEC_DESC_BIT;
    }

    pub fn is_ns_vec(&self) -> bool {
        (self.0 & Self::NS_VEC_DESC_BIT) != 0
    }

    pub fn is_ns_ivec(&self) -> bool {
        (self.0 & 0x0800_0000) != 0
    }

    pub fn is_ns_ovec(&self) -> bool {
        (self.0 & 0x0008_0000) != 0
    }

    /// Getters for lengths (Port of PARAM_UNPACK_IN_LEN/OUT_LEN)
    pub fn in_len(&self) -> usize {
        ((self.0 >> 24) & 0x7) as usize
    }

    pub fn out_len(&self) -> usize {
        ((self.0 >> 16) & 0x7) as usize
    }
}

/// PSA key identifier type (matches `psa_key_id_t` / `uint32_t` in TF-M).
pub type PsaKeyId = u32;

/// PSA algorithm identifier type (matches `psa_algorithm_t` / `uint32_t` in TF-M).
pub type PsaAlgorithm = u32;

/// PSA_ALG_ECDSA(PSA_ALG_SHA_256) - the algorithm value TF-M uses for ES256.
pub const PSA_ALG_ECDSA_SHA256: PsaAlgorithm = 0x0600_0609;

/// Packed AEAD nonce input, matches TF-M `struct tfm_crypto_aead_pack_input`.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct TfmCryptoAeadPackInput {
    pub nonce: [u8; 16],
    pub nonce_length: u32,
}

/// Non-pointer parameters packed into `invec[0]` for every TF-M crypto call.
///
/// Binary-compatible with TF-M `struct tfm_crypto_pack_iovec`.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct TfmCryptoPackIovec {
    pub key_id: PsaKeyId,
    pub alg: PsaAlgorithm,
    pub op_handle: u32,
    pub ad_length: u32,
    pub plaintext_length: u32,
    pub aead_in: TfmCryptoAeadPackInput,
    pub function_id: u16,
    pub step: u16,
    _reserved: [u8; 4],
    pub capacity: u64,
}

impl TfmCryptoPackIovec {
    /// Build a minimal iovec for asymmetric-sign operations.
    pub const fn for_sign_hash(key_id: PsaKeyId, alg: PsaAlgorithm) -> Self {
        Self {
            key_id,
            alg,
            op_handle: 0,
            ad_length: 0,
            plaintext_length: 0,
            aead_in: TfmCryptoAeadPackInput {
                nonce: [0; 16],
                nonce_length: 0,
            },
            _reserved: [0; 4],
            function_id: TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID,
            step: 0,
            capacity: 0,
        }
    }
}

/// TF-M function SID for `psa_sign_hash` (group 7 = ASYM_SIGN, index 2).
pub const TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID: u16 = 0x0702;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_handle_values() {
        assert_eq!(
            ServiceHandle::InternalTrustedStorageService as u32,
            0x40000102
        );
        assert_eq!(ServiceHandle::Crypto as u32, 0x40000100);
        assert_eq!(ServiceHandle::AttestationService as u32, 0x40000103);
    }

    #[test]
    fn ctrl_param_type_only() {
        let cp = CtrlParam::new(42, 0, false, 0, false);
        assert_eq!(cp.unpack_type(), 42);
        assert!(!cp.has_iovec());
        assert_eq!(cp.in_len(), 0);
        assert_eq!(cp.out_len(), 0);
        assert!(!cp.is_ns_ivec());
        assert!(!cp.is_ns_ovec());
        assert!(!cp.is_ns_vec());
    }

    #[test]
    fn ctrl_param_with_iovecs() {
        let cp = CtrlParam::new(1, 2, false, 1, false);
        assert_eq!(cp.unpack_type(), 1);
        assert!(cp.has_iovec());
        assert_eq!(cp.in_len(), 2);
        assert_eq!(cp.out_len(), 1);
    }

    #[test]
    fn ctrl_param_ns_flags() {
        let cp = CtrlParam::new(0, 1, true, 1, true);
        assert!(cp.is_ns_ivec());
        assert!(cp.is_ns_ovec());
    }

    #[test]
    fn ctrl_param_ns_ivec_only() {
        let cp = CtrlParam::new(0, 1, true, 1, false);
        assert!(cp.is_ns_ivec());
        assert!(!cp.is_ns_ovec());
    }

    #[test]
    fn ctrl_param_ns_ovec_only() {
        let cp = CtrlParam::new(0, 1, false, 1, true);
        assert!(!cp.is_ns_ivec());
        assert!(cp.is_ns_ovec());
    }

    #[test]
    fn ctrl_param_set_ns_vec() {
        let mut cp = CtrlParam::new(0, 0, false, 0, false);
        assert!(!cp.is_ns_vec());
        cp.set_ns_vec();
        assert!(cp.is_ns_vec());
    }

    #[test]
    fn ctrl_param_negative_type() {
        // Negative types encoded via i16 should round-trip
        let cp = CtrlParam::new(-1, 0, false, 0, false);
        assert_eq!(cp.unpack_type(), -1);
    }

    #[test]
    fn ctrl_param_max_iovec_lengths() {
        // in_len and out_len are 3-bit fields, max value 7
        let cp = CtrlParam::new(0, 7, false, 7, false);
        assert_eq!(cp.in_len(), 7);
        assert_eq!(cp.out_len(), 7);
        assert!(cp.has_iovec());
    }

    #[test]
    fn tfm_crypto_pack_iovec_for_sign_hash() {
        let iov = TfmCryptoPackIovec::for_sign_hash(42, PSA_ALG_ECDSA_SHA256);
        assert_eq!(iov.key_id, 42);
        assert_eq!(iov.alg, PSA_ALG_ECDSA_SHA256);
        assert_eq!(iov.function_id, TFM_CRYPTO_ASYMMETRIC_SIGN_HASH_SID);
        assert_eq!(iov.op_handle, 0);
        assert_eq!(iov.step, 0);
    }

    #[test]
    fn psa_alg_ecdsa_sha256_value() {
        assert_eq!(PSA_ALG_ECDSA_SHA256, 0x0600_0609);
    }

    #[test]
    fn ff_in_vec_layout() {
        // Verify FFInVec can hold a pointer and length
        let data = [1u8, 2, 3];
        let iv = FFInVec {
            base: data.as_ptr(),
            len: data.len(),
        };
        assert_eq!(iv.len, 3);
        assert!(!iv.base.is_null());
    }

    #[test]
    fn ff_out_vec_layout() {
        let mut data = [0u8; 4];
        let ov = FFOutVec {
            base: data.as_mut_ptr(),
            len: data.len(),
        };
        assert_eq!(ov.len, 4);
        assert!(!ov.base.is_null());
    }
}
