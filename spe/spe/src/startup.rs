// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! SPE Startup helpers

/// Stack seal pattern placed on MSP during secure boot.
/// Veneers verify `[MSP] == STACK_SEAL_PATTERN` to detect re-entrancy.
pub const STACK_SEAL_PATTERN: u32 = 0xFEF5_EDA5;
pub const STACK_SEAL_LO: u32 = STACK_SEAL_PATTERN & 0xFFFF;
pub const STACK_SEAL_HI: u32 = STACK_SEAL_PATTERN >> 16;

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

/// Pushes the stack seal onto MSP and transitions to non-secure state.
///
/// Uses `bxns` (not `blxns`) so no secure state is saved on the stack—the
/// seal remains at `[MSP]` for veneer re-entrancy checks.
///
/// # Safety
/// Caller must have fully initialized the secure environment (SAU, SPM, etc.)
/// and `nonsecure_flash_start` must point to a valid NS vector table.
#[cfg(target_arch = "arm")]
pub unsafe fn jump_to_nonsecure(nonsecure_flash_start: u32) -> ! {
    let nonsecure_start_flash = nonsecure_flash_start as *const u32;
    let nonsecure_sp = unsafe { nonsecure_start_flash.read_volatile() };
    let nonsecure_reset = unsafe { nonsecure_start_flash.add(1).read_volatile() };

    unsafe {
        core::arch::asm!(
            "msr msp_ns, {ns_sp}",
            "push {{{seal}}}",
            "bxns {ns_reset}",
            ns_sp = in(reg) nonsecure_sp,
            ns_reset = in(reg) nonsecure_reset,
            seal = in(reg) STACK_SEAL_PATTERN,
            options(noreturn),
        )
    }
}

#[cfg(not(target_arch = "arm"))]
/// # Safety
/// Non-ARM target stub function for `jump_to_nonsecure`.
pub unsafe fn jump_to_nonsecure(_nonsecure_flash_start: u32) -> ! {
    unimplemented!("Only implemented for ARM architectures");
}
