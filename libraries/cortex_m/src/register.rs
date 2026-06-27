// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Cortex-M core registers

/// Set Main Stack Pointer Limit (MSPLIM).
#[inline(always)]
pub unsafe fn set_msplim(limit: u32) {
    unsafe {
        core::arch::asm!(
            "msr MSPLIM, {limit}",
            limit = in(reg) limit,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Set Process Stack Pointer Limit (PSPLIM).
#[inline(always)]
pub unsafe fn set_psplim(limit: u32) {
    unsafe {
        core::arch::asm!(
            "msr PSPLIM, {limit}",
            limit = in(reg) limit,
            options(nomem, nostack, preserves_flags)
        );
    }
}
