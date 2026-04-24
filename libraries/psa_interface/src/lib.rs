// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#![no_std]

use core::ptr;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum PsaHandle {
    InternalTrustedStorageService = 0x40000102,
    Crypto = 0x40000100,
    AttestationService = 0x40000103,
}

#[repr(C)]
pub enum AttestationServiceType {
    GetToken = 1001,
    GetTokenSize = 1002,
}

// TODO enums
pub type PsaStatus = i32;

const PSA_SUCCESS: PsaStatus = 0;
const PSA_ERROR_INVALID_ARGUMENT: PsaStatus = -135;
const PSA_ERROR_BUFFER_TOO_SMALL: PsaStatus = -138;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PsaInVec {
    pub base: *const u8,
    pub len: usize,
}

impl PsaInVec {
    /// Copy this input vector payload into `dst`.
    ///
    /// Returns the number of bytes copied.
    pub fn read_into(&self, dst: &mut [u8]) -> Result<usize, PsaStatus> {
        if self.len == 0 {
            return Ok(0);
        }

        if self.base.is_null() {
            return Err(PSA_ERROR_INVALID_ARGUMENT);
        }

        if dst.len() < self.len {
            return Err(PSA_ERROR_BUFFER_TOO_SMALL);
        }

        // ### Safety
        // `self.base` is validated as non-null above, and `dst` is guaranteed to
        // be at least `self.len` bytes long. The caller upholds that `self.base`
        // points to a readable memory region of `self.len` bytes.
        unsafe {
            ptr::copy_nonoverlapping(self.base, dst.as_mut_ptr(), self.len);
        }

        Ok(self.len)
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PsaOutVec {
    pub base: *mut u8,
    pub len: usize,
}

impl PsaOutVec {
    /// Copy `src` into this output vector and set `len` to bytes written.
    pub fn write_from(&mut self, src: &[u8]) -> Result<(), PsaStatus> {
        let capacity = self.len;

        if src.is_empty() {
            self.len = 0;
            return Ok(());
        }

        if self.base.is_null() {
            return Err(PSA_ERROR_INVALID_ARGUMENT);
        }

        if src.len() > capacity {
            return Err(PSA_ERROR_BUFFER_TOO_SMALL);
        }

        // ### Safety
        // `self.base` is validated as non-null above, and `capacity` is the
        // caller-provided writable extent for this outvec. We checked
        // `src.len() <= capacity`, so the destination region is large enough.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), self.base, src.len());
        }

        self.len = src.len();
        Ok(())
    }

    pub fn clear(&mut self) -> PsaStatus {
        self.len = 0;
        PSA_SUCCESS
    }
}

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
pub struct VectorDescriptor(u32);

impl VectorDescriptor {
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
