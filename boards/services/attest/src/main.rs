#![no_std]
#![no_main]

use ruspe_psc3::services::attest::{InitialAttestation, Psc3AttestPlatform};
use spe::{
    psa::psa_call::PsaMsg,
    service::Service,
    spm::FlashProcessVectors,
    into_psa_status,
};

static SERVICE: InitialAttestation = InitialAttestation::new(Psc3AttestPlatform);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn call(msg: *const PsaMsg) -> psa_interface::types::PsaStatus {
    let msg = unsafe { &*msg };
    into_psa_status(SERVICE.call(*msg))
}

// External linker symbols for memory initialization
unsafe extern "C" {
    static _szero: *const u32;
    static _ezero: *const u32;
    static _sdata: *const u32;
    static _edata: *const u32;
    static _etext: *const u32;
    static _stack_top: *const u32;
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init() {
    use core::arch::naked_asm;
    naked_asm!(
        "
        // Initialize BSS section (zero out)
        ldr r0, ={szero}        // r0 = start of BSS
        ldr r1, ={ezero}        // r1 = end of BSS
        movs r2, #0             // r2 = 0

    bss_loop:
        cmp r0, r1              // compare pointers
        beq bss_done            // if equal, done
        stm r0!, {{r2}}         // *(r0++) = r2 (zero word)
        b bss_loop

    bss_done:

        // Initialize DATA section (copy from ROM to RAM)
        ldr r0, ={sdata}        // r0 = start of data in RAM
        ldr r1, ={edata}        // r1 = end of data in RAM
        ldr r2, ={etext}        // r2 = start of data in ROM

    data_loop:
        cmp r0, r1              // compare pointers
        beq data_done           // if equal, done
        ldm r2!, {{r3}}         // r3 = *(r2++), load from ROM
        stm r0!, {{r3}}         // *(r0++) = r3, store to RAM
        b data_loop

    data_done:

        // Initialize stack pointer
        ldr sp, ={stack_top}

        // Switch to privileged mode (clear nPRIV bit)
        mrs r0, control         // read CONTROL register
        bic r0, r0, #1          // clear bit 0 (nPRIV)
        msr control, r0         // write back CONTROL
        dsb                     // data synchronization barrier
        isb                     // instruction synchronization barrier

        svc #0                  // supervisor call
        ",
        szero = sym _szero,
        ezero = sym _ezero,
        sdata = sym _sdata,
        edata = sym _edata,
        etext = sym _etext,
        stack_top = sym _stack_top,
    );
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    unsafe(link_section = ".vectors")
)]
// used Ensures that the symbol is kept until the final binary
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static BASE_VECTORS: FlashProcessVectors = FlashProcessVectors { init, call };

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
