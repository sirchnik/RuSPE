// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

/// Memory access behavior: determine which privilege execution mode is used
/// and which Memory Protection Unit (MPU) is used.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum AccessType {
    /// Access using current privilege level and reading from current security
    /// state MPU.
    Current,
    /// Unprivileged access reading from current security state MPU.
    Unprivileged,
    /// Access using current privilege level reading from Non-Secure MPU.
    NonSecure,
    /// Unprivileged access reading from Non-Secure MPU.
    NonSecureUnprivileged,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct TestTarget {
    bits: u32,
    access_type: AccessType,
}

impl TestTarget {
    /// Creates a Test Target Response by executing the appropriate TT
    /// instruction variant.
    pub fn check(addr: *mut u32, access_type: AccessType) -> Self {
        let addr_val = addr as u32;
        let bits: u32 = {
            #[cfg(target_arch = "arm")]
            {
                let bits: u32;

                // Arm TT instructions are only available for supported Arm targets.
                unsafe {
                    match access_type {
                        AccessType::Current => {
                            core::arch::asm!("tt {0}, {1}", out(reg) bits, in(reg) addr_val);
                        }
                        AccessType::Unprivileged => {
                            core::arch::asm!("ttt {0}, {1}", out(reg) bits, in(reg) addr_val);
                        }
                        AccessType::NonSecure => {
                            core::arch::asm!("tta {0}, {1}", out(reg) bits, in(reg) addr_val);
                        }
                        AccessType::NonSecureUnprivileged => {
                            core::arch::asm!("ttat {0}, {1}", out(reg) bits, in(reg) addr_val);
                        }
                    }
                }

                bits
            }

            #[cfg(not(target_arch = "arm"))]
            {
                let _ = (addr_val, access_type);
                0
            }
        };

        TestTarget { bits, access_type }
    }

    /// Checks a memory range. Returns None if boundaries are crossed or range
    /// is invalid.
    pub fn check_range(addr: *mut u32, size: usize, access_type: AccessType) -> Option<Self> {
        if size == 0 {
            return None;
        }
        let begin = addr as usize;
        let end = begin.checked_add(size - 1)?;

        let test_start = TestTarget::check(addr, access_type);

        // 32-byte alignment check: If the range crosses a 32-byte boundary,
        // we must check the end address to ensure security attributes remain identical.
        let single_check = (begin % 32) + size <= 32;

        if single_check {
            Some(test_start)
        } else {
            let test_end = TestTarget::check(end as *mut u32, access_type);
            if test_start.bits != test_end.bits {
                None
            } else {
                Some(test_start)
            }
        }
    }

    // --- Bitfield extraction logic ---

    pub fn readable(&self) -> bool {
        (self.bits >> 18) & 1 != 0
    }

    pub fn read_and_writable(&self) -> bool {
        (self.bits >> 19) & 1 != 0
    }

    pub fn secure(&self) -> bool {
        (self.bits >> 22) & 1 != 0
    }

    pub fn ns_readable(&self) -> bool {
        (self.bits >> 20) & 1 != 0
    }

    pub fn ns_read_and_writable(&self) -> bool {
        (self.bits >> 21) & 1 != 0
    }

    /// MPU Region: Valid if bit 17 (srvalid) is set.
    pub fn mpu_region(&self) -> Option<u8> {
        if (self.bits >> 17) & 1 != 0 {
            Some(((self.bits >> 8) & 0xFF) as u8)
        } else {
            None
        }
    }

    /// SAU Region: Uses the same bit as MPU (SREGION).
    pub fn sau_region(&self) -> Option<u8> {
        self.mpu_region()
    }

    /// IDAU Region: Valid if bit 23 (irvalid) is set.
    pub fn idau_region(&self) -> Option<u8> {
        if (self.bits >> 23) & 1 != 0 {
            Some(((self.bits >> 24) & 0xFF) as u8)
        } else {
            None
        }
    }

    pub fn as_u32(&self) -> u32 {
        self.bits
    }

    pub fn access_type(&self) -> AccessType {
        self.access_type
    }
}
