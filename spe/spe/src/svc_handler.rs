// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]

unsafe extern "Rust" {
    fn __spm_api_handle_svc_dispatch(
        frame: *mut crate::spm_api::SvcStackFrame,
        svc_num: u32,
    ) -> bool;
}

unsafe extern "C" fn svc_handler_dispatch(frame: *mut crate::spm_api::SvcStackFrame, svc_num: u32) {
    if unsafe { __spm_api_handle_svc_dispatch(frame, svc_num) } {
        return;
    }

    panic!("unhandled svc {svc_num}");
}

unsafe extern "C" {
    fn psa_call_thunk();
}

#[cfg(target_arch = "arm")]
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

    // --- SVC_START_PROCESS: switch to unprivileged Thread + PSP ----------
    cmp r1, {SVC_START_PROCESS}
    beq 200f

    // --- SVC_PROCESS_EXIT: return to privileged Thread + MSP ----------------
    cmp r1, {SVC_PROCESS_EXIT}
    beq 201f

    // --- SVC_PSA_CALL: execute psa_call in privileged Thread + MSP ---
    cmp r1, {SVC_PSA_CALL}
    beq 202f
    
    // --- SVC_PSA_CALL_RETURN: return from psa_call ---
    cmp r1, {SVC_PSA_CALL_RETURN}
    beq 203f

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

201: // svc_process_exit
    // Service finished: PSP frame has return value in R0.
    // Copy it to the orphaned MSP frame so the original caller gets it.
    ldr r2, [r0, #0]           // r2 = PSP_frame.R0 (service return value)
    mrs r1, msp                // r1 = MSP (orphaned frame from SVC_START_PROCESS)
    str r2, [r1, #0]          // MSP_frame.R0 = return value

    // Restore privileged Thread mode using MSP.
    mov r0, #0
    msr CONTROL, r0            // nPRIV=0, SPSEL=0
    isb
    bic lr, lr, #4             // EXC_RETURN bit2=0 -> unstack from MSP
    bx lr                      // exception return -> back in privileged caller

202: // svc_psa_call
    mrs r2, msp
    mrs r3, CONTROL
    mrs r12, PSPLIM
    stmdb r2!, {{r0, r3, r12, lr}}
    
    sub r2, r2, #32
    
    ldr r3, [r0, #0]
    str r3, [r2, #0]
    ldr r3, [r0, #4]
    str r3, [r2, #4]
    ldr r3, [r0, #8]
    str r3, [r2, #8]
    ldr r3, [r0, #12]
    str r3, [r2, #12]
    
    mov r3, #0
    str r3, [r2, #16]
    str r3, [r2, #20]
    
    ldr r3, 300f
    str r3, [r2, #24]
    
    mov r3, #1
    lsl r3, r3, #24
    str r3, [r2, #28]
    
    msr msp, r2
    
    mov r3, #0
    msr CONTROL, r3
    isb
    
    ldr lr, 301f
    bx lr

    .align 2
300: .word {psa_call_thunk}
301: .word 0xFFFFFFF9

203: // svc_psa_return
    mrs r2, msp
    
    // Load the original r0 (caller's exception frame pointer) into r0.
    // It is located at offset 32 from the current msp.
    ldr r0, [r2, #32]
    
    // Copy the return values r0-r3 from the current exception frame to the caller's exception frame.
    // We use r1 as a scratch register.
    ldr r1, [r2, #0]
    str r1, [r0, #0]
    ldr r1, [r2, #4]
    str r1, [r0, #4]
    ldr r1, [r2, #8]
    str r1, [r0, #8]
    ldr r1, [r2, #12]
    str r1, [r0, #12]
    
    // Load the original CONTROL, PSPLIM, and EXC_RETURN.
    ldr r3, [r2, #36]
    ldr r1, [r2, #40]
    ldr lr, [r2, #44]
    
    // Adjust MSP (pop the exception frame + saved state).
    add r2, r2, #48
    msr msp, r2
    
    // Restore PSPLIM.
    msr PSPLIM, r1
    
    // If returning to Thread using PSP, set PSP to the caller's exception frame pointer.
    tst lr, #4
    beq 204f
    msr psp, r0
204:
    
    // Restore CONTROL.
    msr CONTROL, r3
    isb
    
    bx lr
        ",
        svc_handler_dispatch = sym svc_handler_dispatch,
        psa_call_thunk = sym psa_call_thunk,
        SVC_START_PROCESS = const crate::spm_api::SVC_START_PROCESS,
        SVC_PROCESS_EXIT = const crate::spm_api::SVC_PROCESS_EXIT,
        SVC_PSA_CALL = const crate::spm_api::SVC_PSA_CALL,
        SVC_PSA_CALL_RETURN = const crate::spm_api::SVC_PSA_CALL_RETURN,
    );
}

#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn svc_handler() {
    unimplemented!("svc_handler is only available on ARM targets")
}
