// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

unsafe extern "C" {
    // _estack is not really a function, but it makes the types work.
    // You should never actually invoke it.
    fn _estack();

    // These constants are defined in the linker script.
    static _szero: *const u32;
    static _ezero: *const u32;
    static _etext: *const u32;
    static _srelocate: *const u32;
    static _erelocate: *const u32;
}

use crate::arch_v7m;

#[derive(Clone, Copy)]
struct FaultStatus {
    cfsr: u32,
    hfsr: u32,
    mmfar: u32,
    bfar: u32,
    control: u32,
    msp: u32,
    psp: u32,
    msplim: u32,
    psplim: u32,
}

unsafe fn read_fault_status() -> FaultStatus {
    use core::arch::asm;

    let mut control: u32;
    let mut msp: u32;
    let mut psp: u32;
    let mut msplim: u32;
    let mut psplim: u32;

    unsafe {
        asm!(
            "mrs {control}, CONTROL",
            "mrs {msp}, MSP",
            "mrs {psp}, PSP",
            "mrs {msplim}, MSPLIM",
            "mrs {psplim}, PSPLIM",
            control = out(reg) control,
            msp = out(reg) msp,
            psp = out(reg) psp,
            msplim = out(reg) msplim,
            psplim = out(reg) psplim,
            options(nomem, nostack, preserves_flags),
        );
    }

    FaultStatus {
        cfsr: unsafe { (0xE000_ED28 as *const u32).read_volatile() },
        hfsr: unsafe { (0xE000_ED2C as *const u32).read_volatile() },
        mmfar: unsafe { (0xE000_ED34 as *const u32).read_volatile() },
        bfar: unsafe { (0xE000_ED38 as *const u32).read_volatile() },
        control,
        msp,
        psp,
        msplim,
        psplim,
    }
}

#[inline(never)]
fn panic_with_fault_status(kind: &str, interrupt_number: u32, stack_overflow: u32) -> ! {
    let status = unsafe { read_fault_status() };

    panic!(
        "{}. ISR {} is active. stack_overflow={} cfsr={:#010x} hfsr={:#010x} mmfar={:#010x} bfar={:#010x} control={:#010x} msp={:#010x} psp={:#010x} msplim={:#010x} psplim={:#010x}",
        kind,
        interrupt_number & 0x1ff,
        stack_overflow,
        status.cfsr,
        status.hfsr,
        status.mmfar,
        status.bfar,
        status.control,
        status.msp,
        status.psp,
        status.msplim,
        status.psplim,
    );
}

unsafe extern "C" fn svc_handler_dispatch(
    frame: *mut spe::psa::psa_svc_api::SvcStackFrame,
    svc_num: u32,
) {
    if unsafe { spe::psa::psa_svc_api::handle_svc(svc_num as u8, &mut *frame) } {
        return;
    }

    unsafe { arch_v7m::svc_handler_arm_v7m() };
}

#[unsafe(link_section = ".stack_buffer")]
#[unsafe(no_mangle)]
static mut STACK_MEMORY: [u8; 0x3200] = [0; 0x3200];

/// Initializes RAM and jumps to main. This is the entry point of the secure firmware.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sec_initialize_ram_jump_to_main() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    // Start by initializing .bss memory. The Tock linker script defines
    // `_szero` and `_ezero` to mark the .bss segment.
    ldr r0, ={sbss}     // r0 = first address of .bss
    ldr r1, ={ebss}     // r1 = first address after .bss

    movs r2, #0         // r2 = 0

100: // bss_init_loop
    cmp r1, r0          // We increment r0. Check if we have reached r1
                        // (end of .bss), and stop if so.
    beq 101f            // If r0 == r1, we are done.
    stm r0!, {{r2}}     // Write a word to the address in r0, and increment r0.
                        // Since r2 contains zero, this will clear the memory
                        // pointed to by r0. Using `stm` (store multiple) with the
                        // bang allows us to also increment r0 automatically.
    b 100b              // Continue the loop.

101: // bss_init_done

    // Now initialize .data memory. This involves coping the values right at the
    // end of the .text section (in flash) into the .data section (in RAM).
    ldr r0, ={sdata}    // r0 = first address of data section in RAM
    ldr r1, ={edata}    // r1 = first address after data section in RAM
    ldr r2, ={etext}    // r2 = address of stored data initial values

200: // data_init_loop
    cmp r1, r0          // We increment r0. Check if we have reached the end
                        // of the data section, and if so we are done.
    beq 201f            // r0 == r1, and we have iterated through the .data section
    ldm r2!, {{r3}}     // r3 = *(r2), r2 += 1. Load the initial value into r3,
                        // and use the bang to increment r2.
    stm r0!, {{r3}}     // *(r0) = r3, r0 += 1. Store the value to memory, and
                        // increment r0.
    b 200b              // Continue the loop.

201: // data_init_done

    // Now that memory has been initialized, we can jump to main() where the
    // board initialization takes place and Rust code starts.
    bl main
        ",
        sbss = sym _szero,
        ebss = sym _ezero,
        sdata = sym _srelocate,
        edata = sym _erelocate,
        etext = sym _etext,
    );
}

#[unsafe(link_section = ".vectors")]
#[used]
pub static BASE_VECTORS: [unsafe extern "C" fn(); 16] = [
    _estack,
    sec_initialize_ram_jump_to_main,
    unhandled_interrupt, // NMI
    hard_fault_handler,  // Hard Fault
    mem_manage_handler,  // MemManage
    bus_fault_handler,   // BusFault
    unhandled_interrupt, // UsageFault
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    svc_handler,         // SVC
    unhandled_interrupt, // DebugMon
    unhandled_interrupt,
    unhandled_interrupt, // PendSV
    unhandled_interrupt, // SysTick
];

#[unsafe(link_section = ".irqs")]
#[used]
pub static IRQS: [unsafe extern "C" fn(); 140] = [unhandled_interrupt; 140];

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
    orr lr, lr, #4              // EXC_RETURN bit2=1 → unstack from PSP
    bx lr                       // exception return → service runs

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
    bic lr, lr, #4             // EXC_RETURN bit2=0 → unstack from MSP
    bx lr                      // exception return → back in privileged caller
        ",
        svc_handler_dispatch = sym svc_handler_dispatch,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn hard_fault_handler() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    // In the case of a hard fault, we want to panic with the active interrupt number.
    // The active interrupt number is stored in the IPSR register, which we can read
    // using the MRS instruction. We then branch to the unhandled_interrupt handler,
    // which will panic with the interrupt number.

    // Check if STKOF in CFSR is set (bit 4). Pass this as arg1.
    ldr r2, =0xE000ED28
    ldr r1, [r2]
    lsrs r1, r1, #4
    ands r1, r1, #1

    mrs r0, ipsr
    b {unhandled_interrupt}
        ",
        unhandled_interrupt = sym hard_fault_handler_real,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn mem_manage_handler() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    movs r1, #0
    mrs r0, ipsr
    b {fault_handler}
        ",
        fault_handler = sym mem_manage_handler_real,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn bus_fault_handler() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    movs r1, #0
    mrs r0, ipsr
    b {fault_handler}
        ",
        fault_handler = sym bus_fault_handler_real,
    );
}

pub unsafe extern "C" fn hard_fault_handler_real(interrupt_number: u32, stack_overflow: u32) {
    panic_with_fault_status("Hard Fault", interrupt_number, stack_overflow);
}

pub unsafe extern "C" fn mem_manage_handler_real(interrupt_number: u32, stack_overflow: u32) {
    panic_with_fault_status("MemManage Fault", interrupt_number, stack_overflow);
}

pub unsafe extern "C" fn bus_fault_handler_real(interrupt_number: u32, stack_overflow: u32) {
    panic_with_fault_status("Bus Fault", interrupt_number, stack_overflow);
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
