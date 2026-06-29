// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

const FAULT_KIND_HARD: u32 = 1;
const FAULT_KIND_MEMMANAGE: u32 = 2;
const FAULT_KIND_BUS: u32 = 3;

#[unsafe(naked)]
pub unsafe extern "C" fn hard_fault_handler() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    movs r3, #{fault_kind}
    b {fault_entry}
        ",
        fault_kind = const FAULT_KIND_HARD,
        fault_entry = sym fault_handler_entry,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn mem_manage_handler() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    movs r3, #{fault_kind}
    b {fault_entry}
        ",
        fault_kind = const FAULT_KIND_MEMMANAGE,
        fault_entry = sym fault_handler_entry,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn bus_fault_handler() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    movs r3, #{fault_kind}
    b {fault_entry}
        ",
        fault_kind = const FAULT_KIND_BUS,
        fault_entry = sym fault_handler_entry,
    );
}

unsafe extern "C" {
    fn _estack();
}

#[unsafe(naked)]
unsafe extern "C" fn fault_handler_entry() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    // r3 carries the fault kind.
    // r0 will be the faulting stack pointer, r1 the IPSR, r2 stack_overflow.
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp

    // Check STKOF in CFSR (bit 20). Pass this as arg2.
    ldr r2, =0xE000ED28
    ldr r2, [r2]
    lsrs r2, r2, #20
    ands r2, r2, #1

    // If stack overflow occurred, reset MSP to _estack so panic! has space to execute
    cmp r2, #1
    bne 1f
    ldr r4, ={_estack}
    msr msp, r4
1:

    mrs r1, ipsr
    b {fault_handler}
        ",
        _estack = sym _estack,
        fault_handler = sym fault_handler_real,
    );
}

unsafe extern "C" fn fault_handler_real(
    _faulting_stack: *const u32,
    interrupt_number: u32,
    stack_overflow: u32,
    kind: u32,
) -> ! {
    let pc = unsafe { *_faulting_stack.add(6) };
    let lr = unsafe { *_faulting_stack.add(5) };
    let r0 = unsafe { *_faulting_stack.add(0) };
    let r1 = unsafe { *_faulting_stack.add(1) };
    panic!(
        "Fault {} ISR {} stk_ovf {}\nPC: {:#010X}, LR: {:#010X}\nR0: {:#010X}, R1: {:#010X}",
        kind,
        interrupt_number & 0x1ff,
        stack_overflow,
        pc,
        lr,
        r0,
        r1
    );
}

pub unsafe extern "C" fn unhandled_interrupt() {
    use core::arch::asm;

    let mut interrupt_number: u32;

    unsafe {
        // IPSR[8:0] holds the currently active interrupt
        asm!(
            "
    mrs {interrupt_number}, ipsr
        ",
            interrupt_number = out(reg) interrupt_number,
            options(nomem, nostack, preserves_flags),
        );
    }

    interrupt_number &= 0x1ff;

    panic!("Unhandled Interrupt. ISR {} is active.", interrupt_number);
}
