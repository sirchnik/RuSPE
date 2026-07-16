// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

/// Call a function in unprivileged Thread mode via SVC, using PSP.
///
/// Sets up an exception frame at `stack_top - 32` with `PC = fn_ptr`, `R0 =
/// arg`, and `LR = 0xFFFF_FFFF` (dummy). It then switches to PSP and triggers
/// `SVC_START_PROCESS`.
///
/// The handler executes the service unprivileged. The service MUST exit by
/// issuing `svc {SVC_PROCESS_EXIT}`, as returning normally (via the dummy `LR`)
/// will fault. The handler then restores privileged mode and returns the
/// service's `R0` result.
///
/// # Safety
/// The caller must guarantee:
/// - *Memory*: `stack_top` must be 8-byte aligned, pointing to valid memory,
///   with at least 32 bytes of space below it for the exception frame.
/// - *Bounds*: `stack_limit <= stack_top - 32`, forming a valid, accessible
///   stack region.
/// - *Execution*: `fn_ptr` must point to valid code that exits via `svc
///   {SVC_PROCESS_EXIT}` (returning normally will fault).
/// - *Isolation*: The MPU must be configured to strictly sandbox the
///   unprivileged execution.
#[cfg(target_arch = "arm")]
pub(crate) unsafe fn svc_call_unpriv(
    fn_ptr: usize,
    arg: usize,
    stack_limit: usize,
    stack_top: usize,
) -> usize {
    use core::arch::asm;

    use crate::spm_api::SVC_START_PROCESS;

    // Build a fake exception frame at (stack_top - 32).
    // Layout: [R0, R1, R2, R3, R12, LR, PC, xPSR]
    let frame_base_addr = stack_top
        .checked_sub(8 * core::mem::size_of::<usize>())
        .expect("service stack too small for exception frame");
    assert!(
        frame_base_addr >= stack_limit,
        "service stack limit overlaps exception frame"
    );
    let frame_base = frame_base_addr as *mut usize;
    // SAFETY: The frame_base is calculated to be strictly within the
    // caller-provided valid stack boundaries (`stack_top` and `stack_limit`).
    // The memory is therefore safe to write to.
    unsafe {
        frame_base.add(0).write_volatile(arg); // R0 = argument
        frame_base.add(1).write_volatile(0); // R1
        frame_base.add(2).write_volatile(0); // R2
        frame_base.add(3).write_volatile(0); // R3
        frame_base.add(4).write_volatile(0); // R12
        frame_base.add(5).write_volatile(0xFFFF_FFFF); // LR = dummy return address
        frame_base.add(6).write_volatile(fn_ptr); // PC = function entry
        frame_base.add(7).write_volatile(0x0100_0000); // xPSR (Thumb bit)
    }

    // Point PSP at the fake frame and bound it with PSPLIM so stack growth
    // faults before it can trample staged service arguments.
    // SAFETY: The `stack_limit` and `frame_base` are valid stack limits as
    // guaranteed by the caller. Setting PSP and PSPLIM configures the hardware
    // for the unprivileged execution context.
    unsafe {
        cortex_m::register::set_psplim(stack_limit as u32);
        asm!(
            "msr psp, {psp}",
            psp = in(reg) frame_base,
            options(nomem, nostack),
        );
    }

    // Issue SVC_START_PROCESS. The handler returns via PSP (service runs).
    // When the service finishes -> SVC_PROCESS_EXIT -> handler returns via
    // MSP -> we land back here with the return value in R0.
    let ret: usize;
    // SAFETY: The SVC instruction transitions the processor to handler mode.
    // The exception handler respects the caller's stack setup, preserving memory
    // safety.
    unsafe {
        asm!(
            "svc {svc_num}",
            svc_num = const SVC_START_PROCESS,
            lateout("r0") ret,
            lateout("r1") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r12") _,
            options(nostack),
        );
    }

    ret
}

#[cfg(not(target_arch = "arm"))]
pub(crate) unsafe fn svc_call_unpriv(
    _fn_ptr: usize,
    _arg: usize,
    _stack_limit: usize,
    _stack_top: usize,
) -> usize {
    unimplemented!("svc_call_unpriv is only implemented for ARM architectures");
}

pub(crate) const EXCEPTION_FRAME_WORDS: usize = 8;
