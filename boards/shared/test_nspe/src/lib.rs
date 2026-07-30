// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

use psa_interface::psa_api;
use psa_interface::types::ServiceHandle;
use psa_veneer_client::PsaVeneerClient;

static OVERFLOW_COUNT: AtomicU32 = AtomicU32::new(0);

/// `SysTick` exception handler that increments the overflow count.
///
/// # Safety
/// This function is an interrupt service routine called by hardware.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn systick_handler() {
    OVERFLOW_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[repr(align(32))]
struct Aligned32<T>(T);

pub fn run_test(writer: &mut dyn Write) {
    let _ = writeln!(writer, "\r\n--- NSPE TEST START ---");
    let _ = writeln!(writer, "profile: default");
    // Activate SysTick for debugging
    // SAFETY: Accessing SysTick peripheral MMIO registers.
    unsafe {
        let rvr = 0xE000_E014 as *mut u32;
        let cvr = 0xE000_E018 as *mut u32;
        let csr = 0xE000_E010 as *mut u32;

        rvr.write_volatile(0x00FF_FFFF); // Max 24-bit value
        cvr.write_volatile(0); // Clear current value
        csr.write_volatile(7); // Enable (1) + TICKINT (2) + Processor Clock (4)

        core::arch::asm!("cpsie i");
    }

    print_version(writer);
    run_attest(writer);
    run_attest_invalid_buffer(writer);
}

fn print_version(writer: &mut dyn Write) {
    let initial_attest_version =
        psa_api::psa_version::<PsaVeneerClient>(ServiceHandle::AttestationService);
    let internal_trusted_storage =
        psa_api::psa_version::<PsaVeneerClient>(ServiceHandle::InternalTrustedStorageService);

    writer
        .write_fmt(format_args!(
            "initial_attest_version: {initial_attest_version}\n"
        ))
        .unwrap();
    writer
        .write_fmt(format_args!(
            "internal_trusted_storage: {internal_trusted_storage}\n"
        ))
        .unwrap();
}

fn run_attest(writer: &mut dyn Write) {
    let challenge = Aligned32([0u8; 32]);

    let mut token_buf = Aligned32([0u8; 512]);

    OVERFLOW_COUNT.store(0, Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // Clear COUNTFLAG by reading SYST_CSR (0xE000_E010) before start
    // SAFETY: Reading SysTick CSR register MMIO.
    let _ = unsafe { core::ptr::read_volatile(0xE000_E010 as *const u32) };
    // SAFETY: Reading SysTick CVR register MMIO.
    let start = unsafe { core::ptr::read_volatile(0xE000_E018 as *const u32) };

    psa_api::psa_initial_attest_get_token::<PsaVeneerClient>(&challenge.0, &mut token_buf.0)
        .unwrap();

    // SAFETY: Reading SysTick CVR register MMIO.
    let end = unsafe { core::ptr::read_volatile(0xE000_E018 as *const u32) };
    // SAFETY: Reading SysTick CSR register MMIO.
    let csr = unsafe { core::ptr::read_volatile(0xE000_E010 as *const u32) };
    let overflows = OVERFLOW_COUNT.load(Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    let effective_overflows = if overflows > 0 {
        overflows
    } else {
        u32::from((csr & (1 << 16)) != 0 || start < end)
    };
    let overflow = effective_overflows > 0;
    let diff = start.wrapping_sub(end) & 0x00FF_FFFF;
    let total_cycles = u64::from(effective_overflows) * 0x0100_0000 + u64::from(diff);

    let _ = write!(writer, "call_start {start}\r\n");
    let _ = write!(writer, "call_end {end}\r\n");
    let _ = write!(writer, "cycles_elapsed {total_cycles}\r\n");
    let _ = write!(writer, "overflow {overflow}\r\n");
    let _ = write!(writer, "overflow_count {effective_overflows}\r\n");

    let _ = write!(writer, "\r\ntoken_buf: ");

    for b in token_buf.0 {
        let _ = write!(writer, "{b:02x}");
    }

    let _ = write!(writer, "\r\n");
}

unsafe extern "C" {
    fn psa_call_veneer();
}

fn run_attest_invalid_buffer(writer: &mut dyn Write) {
    let challenge = Aligned32([0u8; 32]);
    // Use address derived from veneer symbol in secure memory for platform
    // independence
    let invalid_addr = (psa_call_veneer as *const () as usize + 0x100) as *mut u8;
    // SAFETY: Constructing slice from pointer for test assertion.
    let invalid_token_buf = unsafe { core::slice::from_raw_parts_mut(invalid_addr, 512) };

    let res =
        psa_api::psa_initial_attest_get_token::<PsaVeneerClient>(&challenge.0, invalid_token_buf);
    if res.is_err() {
        let _ = writeln!(
            writer,
            "Negative test passed: SPM correctly rejected invalid memory address\r"
        );
    } else {
        let _ = writeln!(
            writer,
            "Negative test FAILED: SPM allowed access to invalid memory address\r"
        );
    }
}

/// Sets the VTOR register to point to the provided vector table.
///
/// # Safety
/// Caller must ensure `offset` is a valid pointer to a vector table aligned per
/// ARM requirements.
pub unsafe fn set_vector_table_offset(offset: *const ()) {
    // VTOR is at 0xE000ED08
    // SAFETY: Writing VTOR register MMIO.
    unsafe { core::ptr::write_volatile(0xE000_ED08 as *mut u32, offset as u32) };
}

/// Handler for unhandled interrupts.
///
/// # Safety
/// Called as interrupt handler.
///
/// # Panics
/// Panics with the active ISR number.
pub unsafe extern "C" fn unhandled_interrupt() {
    use core::arch::asm;
    let mut interrupt_number: u32;
    // SAFETY: Reading IPSR register via assembly.
    unsafe {
        asm!(
            "mrs {}, ipsr",
            out(reg) interrupt_number,
            options(nomem, nostack, preserves_flags),
        );
    }
    interrupt_number &= 0x1ff;
    panic!("Unhandled Interrupt. ISR {interrupt_number} is active.");
}

/// RAM initialization assembly routine before jumping to test `main`.
///
/// # Safety
/// Low-level naked entry point.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn initialize_ram_jump_to_test_main() {
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

unsafe extern "C" {
    static _szero: *const u32;
    static _ezero: *const u32;
    static _etext: *const u32;
    static _srelocate: *const u32;
    static _erelocate: *const u32;
}
