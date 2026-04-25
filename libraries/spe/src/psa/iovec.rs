// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! SPE-side helpers for copying payloads in/out of [`PsaInVec`]/[`PsaOutVec`]
//! buffers, returning [`ErrorCode`] on failure.
//!
//! These extension traits live in SPE (rather than in the FFI-facing
//! `psa_interface` crate) so that all SPE code can stay on
//! `Result<_, ErrorCode>` and only convert to a numeric `PsaStatus` at the
//! veneer boundary.

use core::ptr;

use crate::StatusCode;
use psa_interface::{PsaInVec, PsaOutVec};

pub trait PsaInVecExt {
    /// Copy this input vector payload into `dst`.
    ///
    /// Returns the number of bytes copied.
    fn read_into(&self, dst: &mut [u8]) -> Result<usize, StatusCode>;
}

pub trait PsaOutVecExt {
    /// Copy `src` into this output vector and set `len` to bytes written.
    fn write_from(&mut self, src: &[u8]) -> Result<(), StatusCode>;

    /// Reset the written length of this output vector to zero.
    fn clear(&mut self);
}

impl PsaInVecExt for PsaInVec {
    fn read_into(&self, dst: &mut [u8]) -> Result<usize, StatusCode> {
        if self.len == 0 {
            return Ok(0);
        }

        if self.base.is_null() {
            return Err(StatusCode::InvalidArgument);
        }

        if dst.len() < self.len {
            return Err(StatusCode::BufferTooSmall);
        }

        // ### Safety
        // `self.base` is validated as non-null above, and `dst` is guaranteed
        // to be at least `self.len` bytes long. The caller upholds via the PSA
        // ABI contract that `self.base` points to a readable memory region of
        // `self.len` bytes.
        unsafe {
            ptr::copy_nonoverlapping(self.base, dst.as_mut_ptr(), self.len);
        }

        Ok(self.len)
    }
}

impl PsaOutVecExt for PsaOutVec {
    fn write_from(&mut self, src: &[u8]) -> Result<(), StatusCode> {
        let capacity = self.len;

        if src.is_empty() {
            self.len = 0;
            return Ok(());
        }

        if self.base.is_null() {
            return Err(StatusCode::InvalidArgument);
        }

        if src.len() > capacity {
            return Err(StatusCode::BufferTooSmall);
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

    fn clear(&mut self) {
        self.len = 0;
    }
}
