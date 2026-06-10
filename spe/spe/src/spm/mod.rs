// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

mod spm_fn;
mod spm_ipc;

pub use spm_fn::{Connection, PSA_MAX_IOVEC, SpmCall, SpmError, SpmFn, SpmPlatform};
pub use spm_ipc::{
    EmbeddedProcess, FlashProcess, FlashProcessVectors, IpcProcess, IpcProcessPlatform, SpmIpc,
};

/// Call a function in unprivileged Thread mode via SVC, using PSP.
///
/// Before issuing `SVC_CALL_UNPRIV`, this function:
/// 1. Writes a fabricated exception frame at `stack_top - 32` containing
///    the target `fn_ptr`, `arg`, and `thunk` (return address).
/// 2. Sets PSP to that frame base.
///
/// The SVC handler then:
/// - Sets `CONTROL.nPRIV = 1`
/// - Sets EXC_RETURN SPSEL bit → exception return unstacks from PSP
/// - `bx lr` → hardware pops frame from PSP → service runs unprivileged.
///
/// When the service returns it hits the `thunk` (`svc #0`) which triggers
/// `SVC_ELEVATE`: the handler copies the return value from the PSP frame to
/// the orphaned MSP frame, clears nPRIV, flips EXC_RETURN back to MSP, and
/// returns — landing us back here with the result in R0.
///
/// # Safety
/// - `fn_ptr` must point to valid code in unprivileged-accessible memory.
/// - `thunk` must point to an `svc #0` instruction in unprivileged-accessible
///   memory.
/// - `stack_limit` must be the lowest permitted PSP value for the service.
/// - `stack_top` must be an 8-byte aligned address at the top of RAM accessible
///   to unprivileged code (the service's stack).
#[cfg(all(target_arch = "arm", target_os = "none"))]
pub(crate) unsafe fn svc_call_unpriv(
    fn_ptr: usize,
    arg: usize,
    thunk: usize,
    stack_limit: usize,
    stack_top: usize,
) -> usize {
    use core::arch::asm;

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
    unsafe {
        frame_base.add(0).write_volatile(arg); // R0 = argument
        frame_base.add(1).write_volatile(0); // R1
        frame_base.add(2).write_volatile(0); // R2
        frame_base.add(3).write_volatile(0); // R3
        frame_base.add(4).write_volatile(0); // R12
        frame_base.add(5).write_volatile(thunk); // LR = svc_return thunk
        frame_base.add(6).write_volatile(fn_ptr); // PC = function entry
        frame_base.add(7).write_volatile(0x0100_0000); // xPSR (Thumb bit)
    }

    // Point PSP at the fake frame and bound it with PSPLIM so stack growth
    // faults before it can trample staged service arguments.
    unsafe {
        asm!(
            "msr PSPLIM, {stack_limit}",
            "msr psp, {psp}",
            stack_limit = in(reg) stack_limit,
            psp = in(reg) frame_base,
            options(nomem, nostack),
        );
    }

    // Issue SVC_CALL_UNPRIV. The handler returns via PSP (service runs).
    // When the service finishes → thunk → SVC_ELEVATE → handler returns via
    // MSP → we land back here with the return value in R0.
    let ret: usize;
    unsafe {
        asm!(
            "svc {svc_num}",
            svc_num = const SVC_CALL_UNPRIV,
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

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub(crate) unsafe fn svc_call_unpriv(
    _fn_ptr: usize,
    _arg: usize,
    _thunk: usize,
    _stack_limit: usize,
    _stack_top: usize,
) -> usize {
    panic!("svc_call_unpriv is only available on ARM bare-metal targets")
}
