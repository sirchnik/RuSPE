// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

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

use spe::faults;

#[unsafe(link_section = ".stack_buffer")]
#[unsafe(no_mangle)]
static mut STACK_MEMORY: [u8; 0x1C00] = [0; 0x1C00];

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
    faults::unhandled_interrupt, // NMI
    faults::hard_fault_handler,  // Hard Fault
    faults::mem_manage_handler,  // MemManage
    faults::bus_fault_handler,   // BusFault
    faults::unhandled_interrupt, // UsageFault
    faults::unhandled_interrupt,
    faults::unhandled_interrupt,
    faults::unhandled_interrupt,
    faults::unhandled_interrupt,
    crate::global_spm_api::svc_handler, // SVC
    faults::unhandled_interrupt,        // DebugMon
    faults::unhandled_interrupt,
    faults::unhandled_interrupt, // PendSV
    faults::unhandled_interrupt, // SysTick
];

#[unsafe(link_section = ".irqs")]
#[used]
pub static IRQS: [unsafe extern "C" fn(); 140] = [faults::unhandled_interrupt; 140];
