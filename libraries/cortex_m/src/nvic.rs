// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Cortex-M Nested Vectored Interrupt Controller (NVIC)

use tock_registers::interfaces::{Readable as _, Writeable as _};
use tock_registers::registers::{ReadOnly, ReadWrite};
use tock_registers::{register_bitfields, register_structs};

/// Generates the (u128, u128) tuple used for the NVIC's mask functions
/// `next_pending_with_mask` and `next_pending_with_mask`.
#[macro_export]
macro_rules! interrupt_mask {
    ($($interrupt: expr),+) => {{
        let mut high_interrupt: u128 = 0;
        let mut low_interrupt: u128 = 0;
        $(
            // Validate that the interrupt index is within the high and low
            // interrupt range.
            const{ assert!($interrupt < 256); }
            const{ assert!($interrupt >= 0); }

            if ($interrupt < 128) {
                low_interrupt |= (1u128 << $interrupt)
            }
            else
            {
                high_interrupt |= (1u128 << ($interrupt-128))
            }
        );+
        (high_interrupt, low_interrupt)
    }};
}

register_structs! {
    /// NVIC Registers.
    ///
    /// Note this generic interface exposes all possible NVICs. Most cores will
    /// not implement all NVIC_XXXX registers. If you need to find the number
    /// of NVICs dynamically, consult `ICTR.INTLINESNUM`.
    NvicRegisters {
        (0x000 => _reserved0),

        /// Interrupt Controller Type Register
        (0x004 => ictr: ReadOnly<u32, InterruptControllerType::Register>),

        (0x008 => _reserved1),

        /// Interrupt Set-Enable Registers
        (0x100 => iser: [ReadWrite<u32, NvicSetClear::Register>; 32]),

        /// Interrupt Clear-Enable Registers
        (0x180 => icer: [ReadWrite<u32, NvicSetClear::Register>; 32]),

        /// Interrupt Set-Pending Registers
        (0x200 => ispr: [ReadWrite<u32, NvicSetClear::Register>; 32]),

        /// Interrupt Clear-Pending Registers
        (0x280 => icpr: [ReadWrite<u32, NvicSetClear::Register>; 32]),

        /// Interrupt Active Bit Registers
        (0x300 => iabr: [ReadWrite<u32, NvicSetClear::Register>; 32]),

        /// Interrupt Target Non-secure Registers
        ///
        /// Bit set => interrupt is non-secure, bit clear => interrupt is secure
        (0x380 => itns: [ReadWrite<u32>; 16]),

        (0x3C0 => _reserved2),

        /// Interrupt Priority Registers
        (0x400 => ipr: [ReadWrite<u32, NvicInterruptPriority::Register>; 252]),

        (0x7f0 => _reserved3),

        /// Interrupt Controller Type Register for non-secure world
        (0x20004 => ictr_ns: ReadOnly<u32, InterruptControllerType::Register>),

        (0x20008 => @END),
    }
}

register_bitfields![u32,
    InterruptControllerType [
        /// Total number of interrupt lines in groups of 32
        INTLINESNUM     OFFSET(0)   NUMBITS(4)
    ],

    NvicSetClear [
        /// For register NVIC_XXXXn, access interrupt (m+(32*n)).
        ///  - m takes the values from 31 to 0, except for NVIC_XXXX15, where:
        ///     - m takes the values from 15 to 0
        ///     - register bits[31:16] are reserved, RAZ/WI
        BITS            OFFSET(0)   NUMBITS(32)
    ],

    NvicInterruptPriority [
        /// For register NVIC_IPRn, priority of interrupt number 4n+3.
        PRI_N3          OFFSET(24)  NUMBITS(8),

        /// For register NVIC_IPRn, priority of interrupt number 4n+2.
        PRI_N2          OFFSET(16)  NUMBITS(8),

        /// For register NVIC_IPRn, priority of interrupt number 4n+1.
        PRI_N1          OFFSET(8)   NUMBITS(8),

        /// For register NVIC_IPRn, priority of interrupt number 4n.
        PRI_N0          OFFSET(0)   NUMBITS(8)
    ]
];

const NVIC_BASE: *const NvicRegisters = 0xE000_E000 as *const NvicRegisters;

#[inline]
const fn nvic() -> &'static NvicRegisters {
    unsafe { &*NVIC_BASE }
}

/// Number of valid `NVIC_XXXX` registers. Note this is a ceiling on the number
/// of available interrupts (as this is the number of banks of 32), but the
/// actual number may be less. See NVIC and ICTR documentation for more detail.
fn number_of_nvic_registers() -> usize {
    (nvic().ictr.read(InterruptControllerType::INTLINESNUM) + 1) as usize
}

/// Clear all pending interrupts
///
/// # Safety
/// Calling this function incorrectly can disrupt execution.
pub unsafe fn clear_all_pending() {
    for icpr in nvic().icpr.iter().take(number_of_nvic_registers()) {
        icpr.set(!0);
    }
}

/// Set all interrupts in the range [`start_id`, `end_id`] to be non-secure.
/// Note `end_id` is inclusive.
///
/// # Safety
/// Incorrect configuration can lead to security vulnerabilities.
pub unsafe fn set_interrupt_non_secure(start_id: u32, end_id: u32) {
    for block in (start_id / 32)..=(end_id / 32) {
        let mut mask = nvic().itns[block as usize].get();
        for interrupt in (block * 32)..((block + 1) * 32) {
            if interrupt >= start_id && interrupt <= end_id {
                mask |= 1 << (interrupt % 32);
            }
        }
        nvic().itns[block as usize].set(mask);
    }
}

/// Enable all interrupts
///
/// # Safety
/// Enabling all interrupts can cause unpredictable behavior.
pub unsafe fn enable_all() {
    for icer in nvic().iser.iter().take(number_of_nvic_registers()) {
        icer.set(!0);
    }
}

/// Disable all interrupts
///
/// # Safety
/// Disabling all interrupts can block system functions.
pub unsafe fn disable_all() {
    for icer in nvic().icer.iter().take(number_of_nvic_registers()) {
        icer.set(!0);
    }
}

/// Get the index (0-240) the lowest number pending interrupt, or `None` if none
/// are pending.
///
/// # Safety
/// Depends on valid NVIC configuration.
#[must_use]
pub unsafe fn next_pending() -> Option<u32> {
    for (block, ispr) in nvic()
        .ispr
        .iter()
        .take(number_of_nvic_registers())
        .enumerate()
    {
        let ispr = ispr.get();

        // If there are any high bits there is a pending interrupt
        if ispr != 0 {
            // trailing_zeros == index of first high bit
            let bit = ispr.trailing_zeros();
            #[expect(clippy::cast_possible_truncation, reason = "block index multiplication fits in u32")]
            return Some(block as u32 * 32 + bit);
        }
    }
    None
}

/// Get the index (0-240) the lowest number pending interrupt while ignoring the
/// interrupts that correspond to the bits set in mask, or `None` if none are
/// pending.
///
/// Mask is defined as two `u128` fields,
///   `mask.0` has the bits corresponding to interrupts from 128 to 240.
///   `mask.1` has the bits corresponding to interrupts from 0 to 127.
///
/// # Safety
/// Depends on valid NVIC configuration.
#[must_use]
pub unsafe fn next_pending_with_mask(mask: (u128, u128)) -> Option<u32> {
    for (block, ispr) in nvic()
        .ispr
        .iter()
        .take(number_of_nvic_registers())
        .enumerate()
    {
        let interrupt_mask = if block < 4 { mask.1 } else { mask.0 };
        #[expect(clippy::cast_possible_truncation, reason = "mask shift fits in u32")]
        let ispr_masked = ispr.get() & !((interrupt_mask >> (32 * (block % 4))) as u32);

        // If there are any high bits there is a pending interrupt
        if ispr_masked != 0 {
            // trailing_zeros == index of first high bit
            let bit = ispr_masked.trailing_zeros();
            #[expect(clippy::cast_possible_truncation, reason = "block index multiplication fits in u32")]
            return Some(block as u32 * 32 + bit);
        }
    }
    None
}

/// # Safety
/// Depends on valid NVIC configuration.
#[must_use]
pub unsafe fn has_pending() -> bool {
    nvic()
        .ispr
        .iter()
        .take(number_of_nvic_registers())
        .fold(0, |i, ispr| ispr.get() | i)
        != 0
}

/// Returns whether there are any pending interrupt bits set while ignoring
/// the indices that correspond to the bits set in mask
///
/// Mask is defined as two `u128` fields,
///   `mask.0` has the bits corresponding to interrupts from 128 to 240.
///   `mask.1` has the bits corresponding to interrupts from 0 to 127.
///
/// # Safety
/// Depends on valid NVIC configuration.
#[must_use]
pub unsafe fn has_pending_with_mask(mask: (u128, u128)) -> bool {
    nvic()
        .ispr
        .iter()
        .take(number_of_nvic_registers())
        .enumerate()
        .fold(0, |i, (block, ispr)| {
            let interrupt_mask = if block < 4 { mask.1 } else { mask.0 };
            #[expect(clippy::cast_possible_truncation, reason = "mask shift fits in u32")]
            let mask_u32 = !((interrupt_mask >> (32 * (block % 4))) as u32);
            (ispr.get() & mask_u32) | i
        })
        != 0
}

/// An opaque wrapper for a single NVIC interrupt.
///
/// Hand these out to low-level driver to let them control their own interrupts
/// but not others.
pub struct Nvic(u32);

impl Nvic {
    /// Creates a new `Nvic`.
    ///
    /// # Safety
    /// Marked unsafe because only chip/platform configuration code should be
    /// able to create these.
    #[must_use]
    pub const unsafe fn new(idx: u32) -> Self {
        Self(idx)
    }

    /// Enable the interrupt
    pub fn enable(&self) {
        let idx = self.0 as usize;

        nvic().iser[idx / 32].set(1 << (self.0 & 31));
    }

    /// Disable the interrupt
    pub fn disable(&self) {
        let idx = self.0 as usize;

        nvic().icer[idx / 32].set(1 << (self.0 & 31));
    }

    /// Clear pending state
    pub fn clear_pending(&self) {
        let idx = self.0 as usize;

        nvic().icpr[idx / 32].set(1 << (self.0 & 31));
    }
}
