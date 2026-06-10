// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#[derive(Clone, Copy)]
struct FaultStatus {
    shcsr: u32,
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
        shcsr: unsafe { (0xE000_ED24 as *const u32).read_volatile() },
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
fn panic_with_fault_status(
    kind: u32,
    interrupt_number: u32,
    faulting_stack: *const u32,
    stack_overflow: u32,
) -> ! {
    let status = unsafe { read_fault_status() };
    let interrupt_number = interrupt_number & 0x1ff;

    let (
        stacked_r0,
        stacked_r1,
        stacked_r2,
        stacked_r3,
        stacked_r12,
        stacked_lr,
        stacked_pc,
        stacked_xpsr,
    ) = if stack_overflow != 0 || faulting_stack.is_null() {
        (0, 0, 0, 0, 0, 0, 0, 0)
    } else {
        unsafe {
            (
                *faulting_stack.add(0),
                *faulting_stack.add(1),
                *faulting_stack.add(2),
                *faulting_stack.add(3),
                *faulting_stack.add(4),
                *faulting_stack.add(5),
                *faulting_stack.add(6),
                *faulting_stack.add(7),
            )
        }
    };

    let cfsr = status.cfsr;
    let hfsr = status.hfsr;

    let iaccviol = (cfsr & 0x01) == 0x01;
    let daccviol = (cfsr & 0x02) == 0x02;
    let munstkerr = (cfsr & 0x08) == 0x08;
    let mstkerr = (cfsr & 0x10) == 0x10;
    let mlsperr = (cfsr & 0x20) == 0x20;
    let mmfarvalid = (cfsr & 0x80) == 0x80;

    let ibuserr = ((cfsr >> 8) & 0x01) == 0x01;
    let preciserr = ((cfsr >> 8) & 0x02) == 0x02;
    let impreciserr = ((cfsr >> 8) & 0x04) == 0x04;
    let unstkerr = ((cfsr >> 8) & 0x08) == 0x08;
    let stkerr = ((cfsr >> 8) & 0x10) == 0x10;
    let lsperr = ((cfsr >> 8) & 0x20) == 0x20;
    let bfarvalid = ((cfsr >> 8) & 0x80) == 0x80;

    let undefinstr = ((cfsr >> 16) & 0x01) == 0x01;
    let invstate = ((cfsr >> 16) & 0x02) == 0x02;
    let invpc = ((cfsr >> 16) & 0x04) == 0x04;
    let nocp = ((cfsr >> 16) & 0x08) == 0x08;
    let unaligned = ((cfsr >> 16) & 0x100) == 0x100;
    let divbyzero = ((cfsr >> 16) & 0x200) == 0x200;
    let stkof = ((cfsr >> 16) & 0x10) == 0x10;

    let vecttbl = (hfsr & 0x02) == 0x02;
    let forced = (hfsr & 0x40000000) == 0x40000000;

    let ici_it = (((stacked_xpsr >> 25) & 0x3) << 6) | ((stacked_xpsr >> 10) & 0x3f);
    let thumb_bit = ((stacked_xpsr >> 24) & 0x1) == 1;
    let n_flag = (stacked_xpsr >> 31) & 0x1;
    let z_flag = (stacked_xpsr >> 30) & 0x1;
    let c_flag = (stacked_xpsr >> 29) & 0x1;
    let v_flag = (stacked_xpsr >> 28) & 0x1;
    let q_flag = (stacked_xpsr >> 27) & 0x1;
    let ge_3 = (stacked_xpsr >> 19) & 0x1;
    let ge_2 = (stacked_xpsr >> 18) & 0x1;
    let ge_1 = (stacked_xpsr >> 17) & 0x1;
    let ge_0 = (stacked_xpsr >> 16) & 0x1;
    let exception_number = if stack_overflow != 0 {
        interrupt_number as usize
    } else {
        (stacked_xpsr & 0x1ff) as usize
    };

    panic!(
        "{kind_str} Fault. ISR {interrupt_number} ({interrupt_name}) is active.\r\n\
        	stack_overflow={stack_overflow}\r\n\
        	r0  0x{stacked_r0:x}\r\n\
        	r1  0x{stacked_r1:x}\r\n\
        	r2  0x{stacked_r2:x}\r\n\
        	r3  0x{stacked_r3:x}\r\n\
        	r12 0x{stacked_r12:x}\r\n\
        	lr  0x{stacked_lr:x}\r\n\
        	pc  0x{stacked_pc:x}\r\n\
        	psr 0x{stacked_xpsr:x} [ N {n_flag} Z {z_flag} C {c_flag} V {v_flag} Q {q_flag} GE {ge_3}{ge_2}{ge_1}{ge_0} ; ICI.IT {ici_it} T {thumb_bit} ; Exc {exception_number}-{exception_name} ]\r\n\
        	sp  0x{fault_sp:x}\r\n\
        	SHCSR 0x{shcsr:x}\r\n\
        	CFSR  0x{cfsr:x}\r\n\
        	HFSR  0x{hfsr:x}\r\n\
        	Instruction Access Violation:       {iaccviol}\r\n\
        	Data Access Violation:              {daccviol}\r\n\
        	Memory Management Unstacking Fault: {munstkerr}\r\n\
        	Memory Management Stacking Fault:   {mstkerr}\r\n\
        	Memory Management Lazy FP Fault:    {mlsperr}\r\n\
        	Instruction Bus Error:              {ibuserr}\r\n\
        	Precise Data Bus Error:             {preciserr}\r\n\
        	Imprecise Data Bus Error:           {impreciserr}\r\n\
        	Bus Unstacking Fault:               {unstkerr}\r\n\
        	Bus Stacking Fault:                 {stkerr}\r\n\
        	Bus Lazy FP Fault:                  {lsperr}\r\n\
        	Undefined Instruction Usage Fault:  {undefinstr}\r\n\
        	Invalid State Usage Fault:          {invstate}\r\n\
        	Invalid PC Load Usage Fault:        {invpc}\r\n\
        	No Coprocessor Usage Fault:         {nocp}\r\n\
        	Unaligned Access Usage Fault:       {unaligned}\r\n\
        	Divide By Zero:                     {divbyzero}\r\n\
        	Stack Overflow Usage Fault:         {stkof}\r\n\
        	Bus Fault on Vector Table Read:     {vecttbl}\r\n\
        	Forced Hard Fault:                  {forced}\r\n\
        	Faulting Memory Address: (valid: {mmfarvalid}) {mmfar:#010X}\r\n\
        	Bus Fault Address:       (valid: {bfarvalid}) {bfar:#010X}\r\n\
        	CONTROL 0x{control:x}\r\n\
        	MSP     0x{msp:x}\r\n\
        	PSP     0x{psp:x}\r\n\
        	MSPLIM  0x{msplim:x}\r\n\
        	PSPLIM  0x{psplim:x}\r\n\
        ",
        kind_str = fault_kind_str(kind),
        interrupt_name = ipsr_isr_number_to_str(interrupt_number as usize),
        exception_name = ipsr_isr_number_to_str(exception_number),
        fault_sp = faulting_stack as u32,
        shcsr = status.shcsr,
        cfsr = status.cfsr,
        hfsr = status.hfsr,
        mmfar = status.mmfar,
        bfar = status.bfar,
        control = status.control,
        msp = status.msp,
        psp = status.psp,
        msplim = status.msplim,
        psplim = status.psplim,
    );
}

const FAULT_KIND_HARD: u32 = 1;
const FAULT_KIND_MEMMANAGE: u32 = 2;
const FAULT_KIND_BUS: u32 = 3;

fn fault_kind_str(kind: u32) -> &'static str {
    match kind {
        FAULT_KIND_HARD => "Hard",
        FAULT_KIND_MEMMANAGE => "MemManage",
        FAULT_KIND_BUS => "Bus",
        _ => "Unknown",
    }
}

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

    mrs r1, ipsr
    b {fault_handler}
        ",
        fault_handler = sym fault_handler_real,
    );
}

unsafe extern "C" fn fault_handler_real(
    faulting_stack: *const u32,
    interrupt_number: u32,
    stack_overflow: u32,
    kind: u32,
) -> ! {
    panic_with_fault_status(kind, interrupt_number, faulting_stack, stack_overflow);
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

// Table 2.5
// http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0553a/CHDBIBGJ.html
fn ipsr_isr_number_to_str(isr_number: usize) -> &'static str {
    match isr_number {
        0 => "Thread Mode",
        1 => "Reserved",
        2 => "NMI",
        3 => "HardFault",
        4 => "MemManage",
        5 => "BusFault",
        6 => "UsageFault",
        7..=10 => "Reserved",
        11 => "SVCall",
        12 => "Reserved for Debug",
        13 => "Reserved",
        14 => "PendSV",
        15 => "SysTick",
        16..=255 => "IRQn",
        _ => "(Unknown! Illegal value?)",
    }
}
