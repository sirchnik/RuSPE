// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! SPE Startup helpers

#[cfg(target_arch = "arm")]
type NsResetFn = extern "cmse-nonsecure-call" fn();

#[cfg(not(target_arch = "arm"))]
type NsResetFn = extern "C" fn();

/// Restricts system resets to the secure state and configures exception
/// handling attributes in AIRCR.
///
/// # Safety
/// This function is unsafe because it writes directly to system control
/// registers (SCB AIRCR).
pub unsafe fn configure_aircr() {
    let aircr = 0xe000_ed0c as *mut u32;
    // SAFETY: AIRCR is a valid system control register at this fixed address.
    unsafe {
        let mut value = aircr.read_volatile();
        value &= !(0xFFFF << 16); // Clear VECTKEY
        aircr.write_volatile(value);
        value |= 0x5fa << 16; // VECTKEY
        value |= 1 << 3; // SYSRESETREQS: allow reset request only from secure
        // disallowed!
        value |= 0 << 13; // BFHFNMINS: allow hardfault, busfault, nmi handled in non-secure
        aircr.write_volatile(value);
    }
}

/// Prepares for and returns the function pointer to jump to the non-secure
/// application.
///
/// # Safety
/// This function is unsafe because it performs raw pointer dereferences,
/// sets the non-secure main stack pointer (`MSP_NS`), and transmutes the
/// non-secure reset handler address to an executable function pointer.
pub unsafe fn jump_to_nonsecure(nonsecure_flash_start: u32) -> NsResetFn {
    // SAFETY: Caller guarantees the non-secure vector table pointer is valid;
    // this block performs required privileged operations.
    unsafe {
        let nonsecure_start_flash = nonsecure_flash_start as *const u32;
        let nonsecure_sp = nonsecure_start_flash.read_volatile();
        let nonsecure_reset = nonsecure_start_flash.add(1).read_volatile();

        // Set non-secure main stack pointer on ARM targets.
        #[cfg(target_arch = "arm")]
        core::arch::asm!(
            "msr msp_ns, {nonsecure_sp}",
            nonsecure_sp = in(reg) nonsecure_sp,
            options(nomem, nostack, preserves_flags),
        );

        #[cfg(not(target_arch = "arm"))]
        let _ = nonsecure_sp;

        core::mem::transmute::<*const u32, NsResetFn>(nonsecure_reset as *const u32)
    }
}
