// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

static mut COUNTER: u32 = 0;

#[no_mangle]
pub extern "cmse-nonsecure-entry" fn do_stuff_secure(shared_memory: *mut u32) -> u32 {
    if shared_memory.is_null() {
        return 1;
    }

    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        core::ptr::write_volatile(shared_memory, COUNTER);
    }

    0
}
