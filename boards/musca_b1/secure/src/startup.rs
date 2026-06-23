// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

unsafe extern "C" {
    fn _estack();
    static _szero: *const u32;
    static _ezero: *const u32;
    static _etext: *const u32;
    static _srelocate: *const u32;
    static _erelocate: *const u32;
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".stack_buffer")
)]
#[unsafe(no_mangle)]
static mut STACK_MEMORY: [u8; 0x3000] = [0; 0x3000];

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sec_initialize_ram_jump_to_main() {
    use core::arch::naked_asm;
    naked_asm!(
        "
    ldr r0, ={sbss}
    ldr r1, ={ebss}
    movs r2, #0
100:
    cmp r1, r0
    beq 101f
    stm r0!, {{r2}}
    b 100b
101:
    ldr r0, ={sdata}
    ldr r1, ={edata}
    ldr r2, ={etext}
200:
    cmp r1, r0
    beq 201f
    ldm r2!, {{r3}}
    stm r0!, {{r3}}
    b 200b
201:
    bl main
        ",
        sbss = sym _szero,
        ebss = sym _ezero,
        sdata = sym _srelocate,
        edata = sym _erelocate,
        etext = sym _etext,
    );
}

use spe::faults;

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
    faults::unhandled_interrupt, // SVC
    faults::unhandled_interrupt, // DebugMon
    faults::unhandled_interrupt,
    faults::unhandled_interrupt, // PendSV
    faults::unhandled_interrupt, // SysTick
];

#[unsafe(link_section = ".irqs")]
#[used]
pub static IRQS: [unsafe extern "C" fn(); 140] = [faults::unhandled_interrupt; 140];
