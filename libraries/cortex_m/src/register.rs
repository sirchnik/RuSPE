// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Cortex-M core registers

/// Set Main Stack Pointer Limit (MSPLIM).
///
/// # Safety
/// Incorrect stack limits can lead to memory corruption or crashes.
#[inline]
pub unsafe fn set_msplim(limit: u32) {
    // SAFETY: Writing to the MSPLIM register restricts the main stack boundary.
    // The caller must ensure that the limit is correct to prevent memory corruption
    // or stack overflow.
    unsafe {
        core::arch::asm!(
            "msr MSPLIM, {limit}",
            limit = in(reg) limit,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Set Process Stack Pointer Limit (PSPLIM).
///
/// # Safety
/// Incorrect stack limits can lead to memory corruption or crashes.
#[inline]
pub unsafe fn set_psplim(limit: u32) {
    // SAFETY: Writing to the PSPLIM register restricts the process stack boundary.
    // The caller must ensure that the limit is correct to prevent memory corruption
    // or stack overflow.
    unsafe {
        core::arch::asm!(
            "msr PSPLIM, {limit}",
            limit = in(reg) limit,
            options(nomem, nostack, preserves_flags)
        );
    }
}
