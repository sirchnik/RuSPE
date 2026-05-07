// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

extern "C" {
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

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".stack_buffer"
)]
#[no_mangle]
static mut STACK_MEMORY: [u8; 0x3200] = [0; 0x3200];

/// Initializes RAM and jumps to main. This is the entry point of the secure firmware.
#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
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

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".vectors"
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static BASE_VECTORS: [unsafe extern "C" fn(); 16] = [
    _estack,
    sec_initialize_ram_jump_to_main,
    unhandled_interrupt, // NMI
    hard_fault_handler,  // Hard Fault
    unhandled_interrupt, // MemManage
    unhandled_interrupt, // BusFault
    unhandled_interrupt, // UsageFault
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt, // SVC
    unhandled_interrupt, // DebugMon
    unhandled_interrupt,
    unhandled_interrupt, // PendSV
    unhandled_interrupt, // SysTick
];

#[cfg_attr(all(target_arch = "arm", target_os = "none"), link_section = ".irqs")]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static IRQS: [unsafe extern "C" fn(); 140] = [unhandled_interrupt; 140];

#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
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

pub unsafe extern "C" fn hard_fault_handler_real(interrupt_number: u32, stack_overflow: u32) {
    panic!(
        "Hard Fault. ISR {} is active. stack_overflow={}",
        interrupt_number & 0x1ff,
        stack_overflow
    );
}

#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn unhandled_interrupt() {
    use core::arch::asm;

    let mut interrupt_number: u32;

    unsafe{
    // IPSR[8:0] holds the currently active interrupt
    asm!(
        "
    mrs r0, ipsr
        ",
        out("r0") interrupt_number,
        options(nomem, nostack, preserves_flags),
    );
}

    interrupt_number &= 0x1ff;

    panic!("Unhandled Interrupt. ISR {} is active.", interrupt_number);
}

#[cfg(not(any(doc, all(target_arch = "arm", target_os = "none"))))]
pub unsafe extern "C" fn unhandled_interrupt() {
    unimplemented!()
}

#[cfg(not(any(doc, all(target_arch = "arm", target_os = "none"))))]
pub unsafe extern "C" fn hard_fault_handler() {
    unimplemented!()
}

#[cfg(not(any(doc, all(target_arch = "arm", target_os = "none"))))]
pub unsafe extern "C" fn sec_initialize_ram_jump_to_main() {
    unimplemented!()
}
