// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]

#[allow(unused_imports)]
// Referenced by inline assembly; keep the symbol linked.
use cortexm::syscall::SYSCALL_FIRED;

unsafe extern "C" fn svc_handler_dispatch(
    frame: *mut spe::psa::psa_svc_api::SvcStackFrame,
    svc_num: u32,
) {
    if unsafe { spe::psa::psa_svc_api::handle_svc(svc_num as u8, &mut *frame) } {
        return;
    }

    unsafe { svc_handler_arm_v7m() };
}

#[unsafe(naked)]
pub unsafe extern "C" fn svc_handler() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    // Determine which stack the exception frame is on (EXC_RETURN bit 2).
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp

    // Extract SVC number from the instruction preceding stacked PC.
    ldr r1, [r0, #24]          // r1 = stacked PC
    ldrh r1, [r1, #-2]         // r1 = SVC instruction halfword
    uxtb r1, r1                // r1 = SVC number

    // --- SVC_CALL_UNPRIV (5): switch to unprivileged Thread + PSP ----------
    cmp r1, #5
    beq 200f

    // --- SVC_ELEVATE (0): return to privileged Thread + MSP ----------------
    cmp r1, #0
    beq 201f

    // --- PSA SVCs and any fallback handling --------------------------------
    b {svc_handler_dispatch}

200: // svc_call_unpriv
    // The caller prepared PSP with a fake exception frame before issuing this
    // SVC. We just flip CONTROL and EXC_RETURN to return via PSP unprivileged.
    mov r0, #1
    msr CONTROL, r0             // nPRIV=1
    isb
    orr lr, lr, #4              // EXC_RETURN bit2=1 -> unstack from PSP
    bx lr                       // exception return -> service runs

201: // svc_elevate
    // Service finished: PSP frame has return value in R0.
    // Copy it to the orphaned MSP frame so the original caller gets it.
    ldr r2, [r0, #0]           // r2 = PSP_frame.R0 (service return value)
    mrs r1, msp                // r1 = MSP (orphaned frame from SVC_CALL_UNPRIV)
    str r2, [r1, #0]          // MSP_frame.R0 = return value

    // Restore privileged Thread mode using MSP.
    mov r0, #0
    msr CONTROL, r0            // nPRIV=0, SPSEL=0
    isb
    bic lr, lr, #4             // EXC_RETURN bit2=0 -> unstack from MSP
    bx lr                      // exception return -> back in privileged caller
        ",
        svc_handler_dispatch = sym svc_handler_dispatch,
    );
}

/// Handler of `svc` instructions on ARMv7-M.
#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
#[unsafe(naked)]
pub unsafe extern "C" fn svc_handler_arm_v7m() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    // First check to see which direction we are going in. If the link register
    // (containing EXC_RETURN) has a 1 in the SPSEL bit (meaning the
    // alternative/process stack was in use) then we are coming from a process
    // which has called a syscall.
    ubfx r0, lr, #2, #1               // r0 = (LR & (0x1<<2)) >> 2
    cmp r0, #0                        // r0 (SPSEL bit) =? 0
    bne 100f // to_kernel             // if SPSEL == 1, jump to to_kernel

    // If we get here, then this is a context switch from the kernel to the
    // application. Use the CONTROL register to set the thread mode to
    // unprivileged to run the application.
    //
    // CONTROL[1]: Stack status
    //   0 = Default stack (MSP) is used
    //   1 = Alternate stack is used
    // CONTROL[0]: Mode
    //   0 = Privileged in thread mode
    //   1 = User state in thread mode
    mov r0, #1                        // r0 = 1
    msr CONTROL, r0                   // CONTROL = 1
    // CONTROL writes must be followed by an Instruction Synchronization Barrier
    // (ISB). https://developer.arm.com/documentation/dai0321/latest
    isb

    // The link register is set to the `EXC_RETURN` value on exception entry. To
    // ensure we execute using the process stack we set the SPSEL bit to 1
    // to use the alternate (process) stack.
    orr lr, lr, #4                    // LR = LR | 0b100

    // Switch to the app.
    bx lr

100: // to_kernel
    // An application called a syscall. We mark this in the global variable
    // `SYSCALL_FIRED` which is stored in the syscall file.
    // `UserspaceKernelBoundary` will use this variable to decide why the app
    // stopped executing.
    ldr r0, =SYSCALL_FIRED            // r0 = &SYSCALL_FIRED
    mov r1, #1                        // r1 = 1
    str r1, [r0]                      // *SYSCALL_FIRED = 1

    // Use the CONTROL register to set the thread mode to privileged to switch
    // back to kernel mode.
    //
    // CONTROL[1]: Stack status
    //   0 = Default stack (MSP) is used
    //   1 = Alternate stack is used
    // CONTROL[0]: Mode
    //   0 = Privileged in thread mode
    //   1 = User state in thread mode
    mov r0, #0                        // r0 = 0
    msr CONTROL, r0                   // CONTROL = 0
    // CONTROL writes must be followed by an Instruction Synchronization Barrier
    // (ISB). https://developer.arm.com/documentation/dai0321/latest
    isb

    // The link register is set to the `EXC_RETURN` value on exception entry. To
    // ensure we continue executing in the kernel we ensure the SPSEL bit is set
    // to 0 to use the main (kernel) stack.
    bfc lr, #2, #1                    // LR = LR & !(0x1<<2)

    // Return to the kernel.
    bx lr
        "
    );
}

#[cfg(not(any(doc, all(target_arch = "arm", target_os = "none"))))]
pub unsafe extern "C" fn svc_handler_arm_v7m() {
    unimplemented!()
}
