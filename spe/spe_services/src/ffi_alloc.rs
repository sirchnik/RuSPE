// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![allow(unsafe_code, reason = "Low-level allocation and FFI")]
#![allow(
    static_mut_refs,
    reason = "Single-threaded execution guarantees no concurrent access"
)]
#![allow(clippy::needless_range_loop, reason = "Avoid static_mut_refs warnings")]
#![allow(clippy::multiple_crate_versions, reason = "Workspace level deps")]

use core::ffi::c_void;

const HEAP_SIZE: usize = 1792;
#[repr(C, align(8))]
struct AlignedHeap([u8; HEAP_SIZE]);

static mut HEAP: AlignedHeap = AlignedHeap([0; HEAP_SIZE]);
const MAX_ALLOCS: usize = 64;
static mut ALLOCS: [(u16, u16); MAX_ALLOCS] = [(0, 0); MAX_ALLOCS]; // (offset, size)

/// # Safety
/// Caller must ensure that `size` and `nobj` do not overflow when multiplied.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(nobj: usize, size: usize) -> *mut c_void {
    let total_req = nobj * size;
    if total_req == 0 {
        return core::ptr::null_mut();
    }
    let total = (total_req + 7) & !7; // Align to 8 bytes

    // SAFETY: Accesses static mut HEAP and ALLOCS in single-threaded context.
    unsafe {
        let mut offset = 0;
        'search: while offset + total <= HEAP_SIZE {
            for i in 0..MAX_ALLOCS {
                if ALLOCS[i].1 > 0 {
                    let a_start = ALLOCS[i].0 as usize;
                    let a_end = a_start + (ALLOCS[i].1 as usize);
                    if offset < a_end && offset + total > a_start {
                        offset = a_end;
                        continue 'search;
                    }
                }
            }

            // No overlap found
            for i in 0..MAX_ALLOCS {
                if ALLOCS[i].1 == 0 {
                    ALLOCS[i] = (offset as u16, total as u16);
                    let ptr = core::ptr::addr_of_mut!(HEAP.0).cast::<u8>().add(offset);
                    core::ptr::write_bytes(ptr, 0, total_req);
                    return ptr.cast::<c_void>();
                }
            }
            return core::ptr::null_mut(); // MAX_ALLOCS reached
        }
    }
    core::ptr::null_mut()
}

/// # Safety
/// Caller must ensure that `p` is a pointer returned by `calloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: Accesses static mut HEAP and ALLOCS in single-threaded context.
    unsafe {
        let heap_start = core::ptr::addr_of!(HEAP.0) as usize;
        let p_val = p as usize;
        if p_val < heap_start || p_val >= heap_start + HEAP_SIZE {
            return;
        }
        let p_offset = p_val - heap_start;
        for i in 0..MAX_ALLOCS {
            if ALLOCS[i].1 > 0 && (ALLOCS[i].0 as usize) == p_offset {
                ALLOCS[i].1 = 0;
                return;
            }
        }
    }
}

/// # Safety
/// Provided for critical-section FFI
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn _critical_section_1_0_acquire() -> u8 {
    0
}

/// # Safety
/// Provided for critical-section FFI
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn _critical_section_1_0_release(_state: u8) {}
