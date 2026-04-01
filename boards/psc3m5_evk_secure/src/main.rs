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
    ppc::set_viloation_response(ppc::PPC_CTL::RESP_CFG::BUS_ERROR);

    // TODO limit

    use psc3::ppc::PpcRegion::*;
    let nsec_priv = [
        ProtPeri0Main,
        ProtPeri0Gr0Group,
        ProtPeri0Gr1Group,
        ProtPeri0Gr2Group,
        ProtPeri0Gr3Group,
        ProtPeri0Gr4Group,
        ProtPeri0Gr5Group,
        ProtPeri0Gr0Boot,
        ProtPeri0Gr1Boot,
        ProtPeri0Gr2Boot,
        ProtPeri0Gr3Boot,
        ProtPeri0Gr4Boot,
        ProtPeri0Gr5Boot,
        ProtPeri0Tr,
        ProtPpc0PpcPpcSecure,
        ProtPpc0PpcPpcNonsecure,
        ProtPeriPclk0Main,
        ProtCpuss,
        ProtRamc0Cm33,
        ProtRamc0Boot,
        ProtRamc0RamPwr,
        ProtRamc0Mpc0PpcMpcMain,
        ProtRamc0Mpc0PpcMpcPc,
        ProtRamc0Mpc0PpcMpcRot,
        ProtPromcCm33,
        ProtPromcMpc0PpcMpcMain,
        ProtPromcMpc0PpcMpcPc,
        ProtPromcMpc0PpcMpcRot,
        ProtFlashcBoot,
        ProtFlashcBoot1,
        ProtFlashcMain,
        ProtFlashcDft,
        ProtFlashcEcc,
        ProtFlashcMpc0PpcMpcMain,
        ProtFlashcMpc0PpcMpcPc,
        ProtFlashcMpc0PpcMpcRot,
        ProtFlashcFmCtlFmDft,
        ProtFlashcFmCtlFmBoot,
        ProtFlashcFmCtlFmMain,
        ProtMxcm33Cm33,
        ProtMxcm33Cm33S,
        ProtMxcm33Cm33Ns,
        ProtMxcm33BootPc0,
        ProtMxcm33BootPc1,
        ProtMxcm33BootPc2,
        ProtMxcm33BootPc3,
        ProtMxcm33Boot,
        ProtMxcm33Cm33Int,
        ProtDw0Dw,
        ProtDw1Dw,
        ProtDw0DwCrc,
        ProtDw1DwCrc,
        ProtDw0ChStruct0Ch,
        ProtDw0ChStruct1Ch,
        ProtDw0ChStruct2Ch,
        ProtDw0ChStruct3Ch,
        ProtDw0ChStruct4Ch,
        ProtDw0ChStruct5Ch,
        ProtDw0ChStruct6Ch,
        ProtDw0ChStruct7Ch,
        ProtDw0ChStruct8Ch,
        ProtDw0ChStruct9Ch,
        ProtDw0ChStruct10Ch,
        ProtDw0ChStruct11Ch,
        ProtDw0ChStruct12Ch,
        ProtDw0ChStruct13Ch,
        ProtDw0ChStruct14Ch,
        ProtDw0ChStruct15Ch,
        ProtDw1ChStruct0Ch,
        ProtDw1ChStruct1Ch,
        ProtDw1ChStruct2Ch,
        ProtDw1ChStruct3Ch,
        ProtDw1ChStruct4Ch,
        ProtDw1ChStruct5Ch,
        ProtDw1ChStruct6Ch,
        ProtDw1ChStruct7Ch,
        ProtDw1ChStruct8Ch,
        ProtDw1ChStruct9Ch,
        ProtDw1ChStruct10Ch,
        ProtDw1ChStruct11Ch,
        ProtDw1ChStruct12Ch,
        ProtDw1ChStruct13Ch,
        ProtDw1ChStruct14Ch,
        ProtDw1ChStruct15Ch,
        ProtCpussAllPc,
        ProtCpussDdft,
        ProtCpussCm33S,
        ProtCpussCm33Ns,
        ProtCpussMscInt,
        ProtCpussAp,
        ProtCpussBoot,
        ProtMs0Main,
        ProtMs4Main,
        ProtMs5Main,
        ProtMs7Main,
        ProtMs31Main,
        ProtMsPc0Priv,
        ProtMsPc31Priv,
        ProtMsPc0PrivMir,
        ProtMsPc31PrivMir,
        ProtMscAcg,
        ProtCpussSlCtlGroup,
        ProtIpcStruct0Ipc,
        ProtIpcStruct1Ipc,
        ProtIpcStruct2Ipc,
        ProtIpcStruct3Ipc,
        ProtIpcIntrStruct0Intr,
        ProtIpcIntrStruct1Intr,
        ProtFaultStruct0Main,
        ProtSrssGeneral,
        ProtSrssGeneral2,
        ProtSrssHibData,
        ProtSrssMain,
        ProtSrssSecure,
        ProtRamTrimSrssSram,
        ProtSrssDpll,
        ProtSrssWdt,
        ProtMain,
        ProtPwrmodePwrmode,
        ProtBackupBackup,
        ProtBackupBBreg0,
        ProtBackupBBreg1,
        ProtBackupBBreg2,
        ProtBackupBBreg3,
        ProtBackupBackupSecure,
        ProtCryptoliteMain,
        ProtCryptoliteTrng,
        ProtMxcordic10,
        ProtDebug600Debug600,
        ProtHsiomPrt0Prt,
        ProtHsiomPrt1Prt,
        ProtHsiomPrt2Prt,
        ProtHsiomPrt3Prt,
        ProtHsiomPrt4Prt,
        ProtHsiomPrt5Prt,
        ProtHsiomPrt6Prt,
        ProtHsiomPrt7Prt,
        ProtHsiomPrt8Prt,
        ProtHsiomPrt9Prt,
        ProtHsiomSecurePrt0SecurePrt,
        ProtHsiomSecurePrt1SecurePrt,
        ProtHsiomSecurePrt2SecurePrt,
        ProtHsiomSecurePrt3SecurePrt,
        ProtHsiomSecurePrt4SecurePrt,
        ProtHsiomSecurePrt5SecurePrt,
        ProtHsiomSecurePrt6SecurePrt,
        ProtHsiomSecurePrt7SecurePrt,
        ProtHsiomSecurePrt8SecurePrt,
        ProtHsiomSecurePrt9SecurePrt,
        ProtHsiomAmux,
        ProtHsiomMon,
        ProtGpioPrt0Prt,
        ProtGpioPrt1Prt,
        ProtGpioPrt2Prt,
        ProtGpioPrt3Prt,
        ProtGpioPrt4Prt,
        ProtGpioPrt5Prt,
        ProtGpioPrt6Prt,
        ProtGpioPrt7Prt,
        ProtGpioPrt8Prt,
        ProtGpioPrt9Prt,
        ProtGpioPrt0Cfg,
        ProtGpioPrt1Cfg,
        ProtGpioPrt2Cfg,
        ProtGpioPrt3Cfg,
        ProtGpioPrt4Cfg,
        ProtGpioPrt5Cfg,
        ProtGpioPrt6Cfg,
        ProtGpioPrt7Cfg,
        ProtGpioPrt8Cfg,
        ProtGpioPrt9Cfg,
        ProtGpioSecGpio,
        ProtGpioGpio,
        ProtGpioTest,
        ProtSmartioPrt0Prt,
        ProtSmartioPrt1Prt,
        ProtSmartioPrt2Prt,
        ProtSmartioPrt3Prt,
        ProtSmartioPrt5Prt,
        ProtSmartioPrt6Prt,
        ProtSmartioPrt9Prt,
        ProtLpcomp,
        ProtDft,
        ProtEfuseCtl1,
        ProtEfuseCtl2,
        ProtEfuseCtl3,
        ProtEfuseDataBoot1,
        ProtCanfd0Ch0Ch,
        ProtCanfd0Ch1Ch,
        ProtCanfd0Main,
        ProtCanfd0Buf,
        ProtScb0,
        ProtScb1,
        ProtScb2,
        ProtScb3,
        ProtScb4,
        ProtScb5,
        ProtTcpwm0Grp0Cnt0Cnt,
        ProtTcpwm0Grp0Cnt1Cnt,
        ProtTcpwm0Grp0Cnt2Cnt,
        ProtTcpwm0Grp0Cnt3Cnt,
        ProtTcpwm0Grp1Cnt0Cnt,
        ProtTcpwm0Grp1Cnt1Cnt,
        ProtTcpwm0Grp1Cnt2Cnt,
        ProtTcpwm0Grp1Cnt3Cnt,
        ProtTcpwm0Grp1Cnt4Cnt,
        ProtTcpwm0Grp1Cnt5Cnt,
        ProtTcpwm0Grp1Cnt6Cnt,
        ProtTcpwm0Grp1Cnt7Cnt,
        ProtTcpwm0Grp2Cnt0Cnt,
        ProtTcpwm0Grp2Cnt1Cnt,
        ProtTcpwm0Grp2Cnt2Cnt,
        ProtTcpwm0Grp2Cnt3Cnt,
        ProtTcpwm0Grp2Cnt4Cnt,
        ProtTcpwm0Grp2Cnt5Cnt,
        ProtTcpwm0Grp2Cnt6Cnt,
        ProtTcpwm0Grp2Cnt7Cnt,
        ProtTcpwm0TrAllGfTrAllGf,
        ProtTcpwm0TrAllSyncBypassTrAllSynBypass,
        ProtTcpwm0Boot,
        ProtTcpwm0MotifGrp1Motif0Motif,
        ProtMcpass,
    ];

    for region in nsec_priv {
        ppc::set_trustzone_access(region, true, true, true);
        ppc::set_protection_context(region, 0xFF);
    }
    ppc::lock_protection_contexts();
}

const NONSECURE_START_FLASH: *const [u32; 2] = 0x2201_0100 as *const [u32; 2];

/// Main function called after RAM initialized.
#[no_mangle]
pub unsafe fn main() {
    icache::sys_init_enable_cache();

    psc3::chip::init_gpio_pins();

    // first configure ppc because sau restrict peripheral access to non-secure
    configure_ppc();

    if configure_sau().is_err() {
        loop {
            unsafe {
                core::arch::asm!("nop");
            }
        }
    }

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
