// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

//! Secure startup and services

#![no_std]
#![no_main]
#![feature(abi_cmse_nonsecure_call, cmse_nonsecure_entry)]

use cortexm33::sau;
use psc3::{icache, ppc};

mod io;

extern "Rust" {
    static __veneer_base: ();
    static __veneer_limit: ();
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".stack_buffer"
)]
#[no_mangle]
static mut STACK_MEMORY: [u8; 0x3000] = [0; 0x3000];

// These constants are defined in the linker script.
extern "C" {
    static _szero: *const u32;
    static _ezero: *const u32;
    static _etext: *const u32;
    static _srelocate: *const u32;
    static _erelocate: *const u32;
}
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

extern "C" {
    // _estack is not really a function, but it makes the types work
    // You should never actually invoke it!!
    fn _estack();
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".vectors"
)]
// used Ensures that the symbol is kept until the final binary
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

    mrs r0, ipsr
    b {unhandled_interrupt}
        ",
        unhandled_interrupt = sym unhandled_interrupt,
    );
}

#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn unhandled_interrupt() {
    use core::arch::asm;
    let mut interrupt_number: u32;

    // IPSR[8:0] holds the currently active interrupt
    asm!(
        "
    mrs r0, ipsr
        ",
        out("r0") interrupt_number,
        options(nomem, nostack, preserves_flags),
    );

    interrupt_number &= 0x1ff;

    panic!("Unhandled Interrupt. ISR {} is active.", interrupt_number);
}

unsafe fn configure_sau() -> Result<(), sau::SauError> {
    let mut sau = sau::new();

    sau.set_region(
        0,
        sau::SauRegion {
            base_address: 0x2201_0100,
            limit_address: 0x2203_FFFF,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )?;

    sau.set_region(
        1,
        sau::SauRegion {
            base_address: 0x3200_FF00,
            limit_address: 0x3200_FFFF,
            attribute: sau::SauRegionAttribute::NonSecureCallable,
        },
    )?;

    sau.set_region(
        2,
        sau::SauRegion {
            base_address: 0x2400_4000,
            limit_address: 0x2400_EFFF,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )?;

    sau.set_region(
        3,
        sau::SauRegion {
            base_address: 0x2400_F000,
            limit_address: 0x2400_FFFF,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )?;

    // TODO limit
    sau.set_region(
        4,
        sau::SauRegion {
            base_address: 0x4200_0000,
            limit_address: 0x4FFF_FFFF,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )?;

    sau.enable();

    Ok(())
}

fn configure_ppc() {
    ppc::set_viloation_response(ppc::PPC_CTL::RESP_CFG::RZWI);

    // TODO limit
    use ppc::PpcRegion::*;
    let nsec_priv = [
        Peri0Main,
        Peri0Gr0Group,
        Peri0Gr1Group,
        Peri0Gr2Group,
        Peri0Gr3Group,
        Peri0Gr4Group,
        Peri0Gr5Group,
        Peri0Gr0Boot,
        Peri0Gr1Boot,
        Peri0Gr2Boot,
        Peri0Gr3Boot,
        Peri0Gr4Boot,
        Peri0Gr5Boot,
        Peri0Tr,
        PeriPclk0Main,
        Cpuss,
        Ramc0Cm33,
        Ramc0Boot,
        Ramc0RamPwr,
        PromcCm33,
        FlashcBoot,
        FlashcBoot1,
        FlashcMain,
        FlashcDft,
        FlashcEcc,
        Mxcm33Cm33,
        Mxcm33Cm33S,
        Mxcm33Cm33Ns,
        Mxcm33BootPc0,
        Mxcm33BootPc1,
        Mxcm33BootPc2,
        Mxcm33BootPc3,
        Mxcm33Boot,
        Mxcm33Cm33Int,
        Dw0Dw,
        Dw1Dw,
        Dw0DwCrc,
        Dw1DwCrc,
        CpussAllPc,
        CpussDdft,
        CpussCm33S,
        CpussCm33Ns,
        CpussMscInt,
        CpussAp,
        CpussBoot,
        Ms0Main,
        Ms4Main,
        Ms5Main,
        Ms7Main,
        Ms31Main,
        MsPc0Priv,
        MsPc31Priv,
        MsPc0PrivMir,
        MsPc31PrivMir,
        MscAcg,
        IpcStruct0Ipc,
        IpcStruct1Ipc,
        IpcStruct2Ipc,
        IpcStruct3Ipc,
        SrssGeneral,
        SrssGeneral2,
        SrssHibData,
        SrssMain,
        SrssSecure,
        SrssDpll,
        SrssWdt,
        Main,
        BackupBackup,
        BackupBBreg0,
        BackupBBreg1,
        BackupBBreg2,
        BackupBBreg3,
        CryptoliteMain,
        CryptoliteTrng,
        Mxcordic10,
        HsiomPrt0Prt,
        HsiomPrt1Prt,
        HsiomPrt2Prt,
        HsiomPrt3Prt,
        HsiomPrt4Prt,
        HsiomPrt5Prt,
        HsiomPrt6Prt,
        HsiomPrt7Prt,
        HsiomPrt8Prt,
        HsiomPrt9Prt,
        HsiomAmux,
        HsiomMon,
        GpioPrt0Prt,
        GpioPrt1Prt,
        GpioPrt2Prt,
        GpioPrt3Prt,
        GpioPrt4Prt,
        GpioPrt5Prt,
        GpioPrt6Prt,
        GpioPrt7Prt,
        GpioPrt8Prt,
        GpioPrt9Prt,
        GpioPrt0Cfg,
        GpioPrt1Cfg,
        GpioPrt2Cfg,
        GpioPrt3Cfg,
        GpioPrt4Cfg,
        GpioPrt5Cfg,
        GpioPrt6Cfg,
        GpioPrt7Cfg,
        GpioPrt8Cfg,
        GpioPrt9Cfg,
        GpioSecGpio,
        GpioGpio,
        GpioTest,
        SmartioPrt0Prt,
        SmartioPrt1Prt,
        SmartioPrt2Prt,
        SmartioPrt3Prt,
        SmartioPrt5Prt,
        SmartioPrt6Prt,
        SmartioPrt9Prt,
        Lpcomp,
        Dft,
        EfuseCtl1,
        EfuseCtl2,
        EfuseCtl3,
        EfuseDataBoot1,
        Canfd0Ch0Ch,
        Canfd0Ch1Ch,
        Canfd0Main,
        Canfd0Buf,
        Scb0,
        Scb1,
        Scb2,
        Scb3,
        Scb4,
        Scb5,
        Tcpwm0Boot,
        Mcpass,
    ];

    for region in nsec_priv {
        ppc::set_trustzone_access(region, true, true);
        ppc::set_protection_context(region, 0xFF);
    }
    ppc::lock_protection_contexts();
}

const NONSECURE_START_FLASH: *const [u32; 2] = 0x2201_0100 as *const [u32; 2];
const NONSECURE_END_FLASH: *const u32 = 0x2204_0000 as *const u32;

/// Main function called after RAM initialized.
#[no_mangle]
pub unsafe fn main() {
    icache::sys_init_enable_cache();
    if configure_sau().is_err() {
        loop {
            unsafe {
                core::arch::asm!("nop");
            }
        }
    }

    configure_ppc();

    psc3::chip::init_gpio_pins();

    unsafe {
        let [nonsecure_sp, nonsecure_reset] = NONSECURE_START_FLASH.read_volatile();

        core::arch::asm!(
            "msr msp, {nonsecure_sp}",
            nonsecure_sp = in(reg) nonsecure_sp,
            options(nomem, nostack, preserves_flags),
        );

        let nonsecure_reset = core::mem::transmute::<*const u32, extern "cmse-nonsecure-call" fn()>(
            nonsecure_reset as *const u32,
        );

        nonsecure_reset();
    }
}

static mut COUNTER: u32 = 0;

#[no_mangle]
extern "cmse-nonsecure-entry" fn do_stuff_secure(num: u32) -> u32 {
    unsafe {
        COUNTER += num;
        COUNTER
    }
}
