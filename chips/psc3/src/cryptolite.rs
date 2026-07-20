// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use helpers::static_ref::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::registers::ReadWrite;
use tock_registers::{register_bitfields, register_structs};

// CRYPTOLITE peripheral driver for PSC3.
//
// This module currently exposes TRNG control and data-read APIs.
//
// Typical TRNG usage sequence:
// 1. Create a `Cryptolite` instance.
// 2. Call `trng_init(None)` or provide a custom `TrngConfig`.
// 3. Call `trng_enable()`.
// 4. Call `trng_read_data()`.
// 5. Call `trng_disable()` when finished.
//
// `trng_read_data()` returns `Err(CryptoliteErr::TrngUnhealthy)` when
// adaptive proportion or repetition count checks detect unhealthy entropy.

register_structs! {
    /// CRYPTOLITE
    CryptoliteRegisters {
        /// Control
        (0x000 => ctl: ReadWrite<u32, CTL::Register>),
        /// Status
        (0x004 => status: ReadWrite<u32, STATUS::Register>),
        (0x008 => _reserved0),
        /// AES descriptor pointer
        (0x040 => aes_descr: ReadWrite<u32, AES_DESCR::Register>),
        (0x044 => _reserved1),
        /// VU descriptor pointer
        (0x080 => vu_descr: ReadWrite<u32, VU_DESCR::Register>),
        (0x084 => _reserved2),
        /// SHA descriptor pointer
        (0x0C0 => sha_descr: ReadWrite<u32, SHA_DESCR::Register>),
        (0x0C4 => _reserved3),
        /// Error interrupt
        (0x0F0 => intr_error: ReadWrite<u32, INTR_ERROR::Register>),
        /// Error interrupt set
        (0x0F4 => intr_error_set: ReadWrite<u32, INTR_ERROR_SET::Register>),
        /// Error interrupt mask
        (0x0F8 => intr_error_mask: ReadWrite<u32, INTR_ERROR_MASK::Register>),
        /// Error interrupt masked
        (0x0FC => intr_error_masked: ReadWrite<u32, INTR_ERROR_MASKED::Register>),
        /// TRNG control 0
        (0x100 => trng_ctl0: ReadWrite<u32, TRNG_CTL0::Register>),
        /// TRNG control 1
        (0x104 => trng_ctl1: ReadWrite<u32, TRNG_CTL1::Register>),
        (0x108 => _reserved4),
        /// TRNG status
        (0x10C => trng_status: ReadWrite<u32, TRNG_STATUS::Register>),
        /// TRNG result
        (0x110 => trng_result: ReadWrite<u32, TRNG_RESULT::Register>),
        (0x114 => _reserved5),
        /// TRNG GARO control
        (0x120 => trng_garo_ctl: ReadWrite<u32, TRNG_GARO_CTL::Register>),
        /// TRNG FIRO control
        (0x124 => trng_firo_ctl: ReadWrite<u32, TRNG_FIRO_CTL::Register>),
        (0x128 => _reserved6),
        /// TRNG monitor control
        (0x140 => trng_mon_ctl: ReadWrite<u32, TRNG_MON_CTL::Register>),
        (0x144 => _reserved7),
        /// TRNG monitor RC control
        (0x150 => trng_mon_rc_ctl: ReadWrite<u32, TRNG_MON_RC_CTL::Register>),
        (0x154 => _reserved8),
        /// TRNG monitor RC status 0
        (0x158 => trng_mon_rc_status0: ReadWrite<u32, TRNG_MON_RC_STATUS0::Register>),
        /// TRNG monitor RC status 1
        (0x15C => trng_mon_rc_status1: ReadWrite<u32, TRNG_MON_RC_STATUS1::Register>),
        /// TRNG monitor AP control
        (0x160 => trng_mon_ap_ctl: ReadWrite<u32, TRNG_MON_AP_CTL::Register>),
        (0x164 => _reserved9),
        /// TRNG monitor AP status 0
        (0x168 => trng_mon_ap_status0: ReadWrite<u32, TRNG_MON_AP_STATUS0::Register>),
        /// TRNG monitor AP status 1
        (0x16C => trng_mon_ap_status1: ReadWrite<u32, TRNG_MON_AP_STATUS1::Register>),
        (0x170 => _reserved10),
        /// TRNG interrupt
        (0x1F0 => intr_trng: ReadWrite<u32, INTR_TRNG::Register>),
        /// TRNG Interrupt set
        (0x1F4 => intr_trng_set: ReadWrite<u32, INTR_TRNG_SET::Register>),
        /// TRNG Interrupt mask
        (0x1F8 => intr_trng_mask: ReadWrite<u32, INTR_TRNG_MASK::Register>),
        /// TRNG Interrupt masked
        (0x1FC => intr_trng_masked: ReadWrite<u32, INTR_TRNG_MASKED::Register>),
        (0x200 => @END),
    }
}
register_bitfields![u32,
CTL [
    /// User/privileged access control:
    /// '0': user mode.
    /// '1': privileged mode.
    ///
    /// This field is set with the user/privileged access control of the transaction that writes any (including possible memory holes in the IP aperture) of the CRYPTO component registers; i.e. the access control is inherited from the write transaction and not specified by the transaction write data.
    ///
    /// All CRYPTO component master transactions use the P field for the user/privileged access control ('hprot[1]').
    P OFFSET(0) NUMBITS(1) [],
    /// Secure/on-secure access control:
    /// '0': secure.
    /// '1': non-secure.
    ///
    /// This field is set with the secure/non-secure access control of the transaction that writes  any (including possible memory holes in the IP aperture) of the CRYPTO component registers; i.e. the access control is inherited from the write transaction and not specified by the transaction write data.
    ///
    /// All CRYPTO component master transactions use the NS field for the secure/non-secure access control ('hprot[4]').
    NS OFFSET(1) NUMBITS(1) [],
    /// Protection context.
    ///
    /// This field is set with the protection context of the transaction that writes any (including possible memory holes in the IP aperture) of the CRYPTO component registers; i.e. the context is inherited from the write transaction and not specified by the transaction write data.
    ///
    /// All CRYPTO component master transactions use the PC field for the protection context.
    PC OFFSET(4) NUMBITS(4) [],
    /// Master identifier of the cryptography IP. This is a design time configurable parameter.
    MS OFFSET(8) NUMBITS(4) []
],
STATUS [
    /// Busy indication:
    /// '0': IP not busy.
    /// '1': IP busy (AES, SHA or VU functionality (TRNG functionality NOT included)).
    BUSY OFFSET(0) NUMBITS(1) []
],
AES_DESCR [
    /// AES descriptor pointer. The descriptor points to a structure with 32-bit words:
    /// Word 0: Pointer to a 128-bit AES key.
    /// Word 1: Pointer to a 128-bit source/plaintext.
    /// Word 2: Pointer to a 128-bit destination/ciphertext.
    ///
    /// A write to this register automatically starts a 128-bit AES encryption in ECB mode. The write ONLY takes effect when the IP is NOT busy (STATUS.BUSY is '0'). The write will be made pending/blocked as long as the IP is busy.
    ///
    /// Note: the pointers must be 4B aligned.
    ///
    /// Note: HW updates this field when the AES engine is busy.
    PTR OFFSET(2) NUMBITS(30) []
],
VU_DESCR [
    /// VU descriptor pointer. The descriptor points to a structure with 32-bit words:
    /// Word 0: Control word. Specifies operand size in 32-bit word multiples.
    /// - WORD[7:0]: Source operand 0 32-bit words (minus 1).
    /// - WORD[15:8]: Source operand 1 32-bit words (minus 1).
    /// - WORD[24:16]: Destination operand 32-bit words (minus 1).
    /// - WORD[31:28]: Opcode. '0': multiplication (MUL), '1': addition (ADD), '2': subtraction (SUB), '3': exclusive or (XOR), '4': binary multiplication (XMUL), '5': logical shift right by 1 (LSR1), '6': logical shift left by 1 (LSL1), '7': logical shift right (LSR), '8': conditional syubtraction (COND_SUB). '9': move (MOV).
    /// Word 1: Pointer to source 0.
    /// Word 2: Pointer to source 1.
    /// Word 3: Pointer to destination.
    ///
    /// A write to this register automatically starts a VU operation. The write ONLY takes effect when the IP is NOT busy (STATUS.BUSY is '0'). The write will be made pending/blocked as long as the IP is busy.
    ///
    /// Note: the pointers must be 4B aligned.
    ///
    /// Note: HW updates this field when the VU engine is busy.
    PTR OFFSET(2) NUMBITS(30) []
],
SHA_DESCR [
    /// SHA-256 descriptor pointer. The descriptor points to a structure with 32-bit words:
    /// For message schedule function:
    /// Word 0: Control word.
    /// - WORD0[28]: '0' for message schedule function.
    /// Word 1: Pointer to 512 b message chunk (input).
    /// Word 2: Pointer to 64 * 32 b word message schedule array (output).
    /// For process function:
    /// Word 0: Control word.
    /// - WORD0[28]: '1' for process function.
    /// Word 1: Pointer to 8 * 32 b word current hash value (input) and new hash value (output).
    /// Word 2: Pointer to 64 * 32 b word message schedule array (input).
    ///
    /// A write to this register automatically starts a SHA-256 operation. The write ONLY takes effect when the IP is NOT busy (STATUS.BUSY is '0'). The write will be made pending/blocked as long as the IP is busy.
    ///
    /// Note: the pointers must be 32-bit word aligned.
    ///
    /// Note: HW updates this field when the SHA-256 engine is busy.
    PTR OFFSET(2) NUMBITS(30) []
],
INTR_ERROR [
    /// AHB-Lite master interface bus error or ECC error. Note that the IP terminates its AES, SHA or VU functionality when it detects an error.
    ///
    /// Note: The error is sticky. This allows SW to check for an error after a series of operations, rather than checking after every individual operation.
    BUS_ERROR OFFSET(0) NUMBITS(1) []
],
INTR_ERROR_SET [
    /// Write this field with '1' to set corresponding INTR_ERROR field to '1' (a write of '0' has no effect).
    BUS_ERROR OFFSET(0) NUMBITS(1) []
],
INTR_ERROR_MASK [
    /// Mask for corresponding field in INTR_ERROR register.
    BUS_ERROR OFFSET(0) NUMBITS(1) []
],
INTR_ERROR_MASKED [
    /// Logical and of corresponding INTR_ERROR and INTR_ERROR_MASK fields.
    BUS_ERROR OFFSET(0) NUMBITS(1) []
],
TRNG_CTL0 [
    /// Specifies the clock divider that is used to sample oscillator data. This clock divider is wrt. The IP clock.
    /// '0': sample clock is the IP clock.
    /// '1': sample clock is the IP clock divided by 2.
    /// ...
    /// '255': sample clock is the IP clock divided by 256.
    SAMPLE_CLOCK_DIV OFFSET(0) NUMBITS(8) [],
    /// Specifies the clock divider that is used to produce reduced bits.
    /// '0': 1 reduced bit is produced for each sample.
    /// '1': 1 reduced bit is produced for each 2 samples.
    /// ...
    /// '255': 1 reduced bit is produced for each 256 samples.
    ///
    /// The reduced bits are considered random bits and shifted into TRNG_RESULT.DATA.
    RED_CLOCK_DIV OFFSET(8) NUMBITS(8) [],
    /// Specifies an initialization delay: number of removed/dropped samples before reduced bits are generated. This field should be programmed in the range [1, 255]. After starting the oscillators, at least the first 2 samples should be removed/dropped to clear the state of internal synchronizers. In addition, it is advised to drop at least the second 2 samples from the oscillators (to circumvent the semi-predictable oscillator startup behavior). This result in the default field value of '3'. Field encoding is as follows:
    /// '0': 1 sample is dropped.
    /// '1': 2 samples are dropped.
    /// ...
    /// '255': 256 samples are dropped.
    ///
    /// The INTR.INITIALIZED interrupt cause is set to '1', when the initialization delay is passed.
    INIT_DELAY OFFSET(16) NUMBITS(8) [],
    /// Specifies if the 'von Neumann corrector' is disabled or enabled:
    /// '0': disabled.
    /// '1': enabled.
    /// The 'von Neumann corrector' post-processes the reduced bits to remove a '0' or '1' bias. The corrector operates on reduced bit pairs ('oldest bit, newest bit'):
    /// '00': no bit is produced.
    /// '01': '0' bit is produced (oldest bit).
    /// '10': '1' bit is produced (oldest bit).
    /// '11': no bit is produced.
    /// Note that the corrector produces bits at a random pace and at a frequency that is 1/4 of the reduced bit frequency (reduced bits are processed in pairs, and half of the pairs do NOT produce a bit).
    VON_NEUMANN_CORR OFFSET(24) NUMBITS(1) [],
    /// Specifies if the feedback of the reducution state is enabled:
    /// '0': Disabled.
    /// '1': Enabled.
    ///
    /// Note: This field is added in the 'mxcryptolite' IP to address CDT#337111, in which it was observed that the reduction state feedback reduces  the effectiveness of the 'von Neumann corrector'. The default value is '1' to provide backward compatibility.
    FEEDBACK_EN OFFSET(25) NUMBITS(1) [],
    /// Specifies if TRNG functionality is stopped on an adaptive proportion test detection (when HW sets INTR_ERROR.TRNG_AP_DETECT to '1'):
    /// '0': Functionality is NOT stopped.
    /// '1': Functionality is stopped (TRNG_CTL1 fields are set to '0' by HW). The DAS bitstream is set to '0'.
    STOP_ON_AP_DETECT OFFSET(28) NUMBITS(1) [],
    /// Specifies if TRNG functionality is stopped on a repetition count test detection (when HW sets INTR_ERROR.TRNG_RC_DETECT to '1'):
    /// '0': Functionality is NOT stopped.
    /// '1': Functionality is stopped (TRNG_CTL1 fields are set to '0' by HW). The DAS bitstream is set to '0'.
    STOP_ON_RC_DETECT OFFSET(29) NUMBITS(1) []
],
TRNG_CTL1 [
    /// FW sets this field to '1' to enable the ring oscillator with 11 inverters.
    RO11_EN OFFSET(0) NUMBITS(1) [],
    /// FW sets this field to '1' to enable the ring oscillator with 15 inverters.
    RO15_EN OFFSET(1) NUMBITS(1) [],
    /// FW sets this field to '1' to enable the fixed Galois ring oscillator with 15 inverters.
    GARO15_EN OFFSET(2) NUMBITS(1) [],
    /// FW sets this field to '1' to enable the programmable Galois ring oscillator with up to 31 inverters. The TRNG_GARO_CTL register specifies the programmable polynomial.
    GARO31_EN OFFSET(3) NUMBITS(1) [],
    /// FW sets this field to '1' to enable the fixed Fibonacci ring oscillator with 15 inverters.
    FIRO15_EN OFFSET(4) NUMBITS(1) [],
    /// FW sets this field to '1' to enable the programmable Fibonacci ring oscillator with up to 31 inverters. The TRNG_FIRO_CTL register specifies the programmable polynomial.
    FIRO31_EN OFFSET(5) NUMBITS(1) []
],
TRNG_STATUS [
    /// Reflects the state of the true random number generator:
    /// '0': Not initialized (TRNG_CTL0.INIT_DELAY has NOT passed).
    /// '1': Initialized (TRNG_CTL0.INIT_DELAY has passed).
    INITIALIZED OFFSET(0) NUMBITS(1) []
],
TRNG_RESULT [
    /// Generated 32-bit true random number. The INTR.DATA_AVAILABLE interrupt cause is activated when the number is generated.
    DATA OFFSET(0) NUMBITS(32) []
],
TRNG_GARO_CTL [
    /// Polynomial for programmable Galois ring oscillator. The polynomial is represented WITHOUT the high order bit (this bit is always assumed '1'). The polynomial should be aligned such that the more significant bits (bit 30 and down) contain the polynomial and the less significant bits (bit 0 and up) contain padding '0's.
    ///
    /// Note: Default value per GESC#113.
    POLYNOMIAL OFFSET(0) NUMBITS(31) []
],
TRNG_FIRO_CTL [
    /// Polynomial for programmable Fibonacci ring oscillator. The polynomial is represented WITHOUT the high order bit (this bit is always assumed '1'). The polynomial should be aligned such that the more significant bits (bit 30 and down) contain the polynomial and the less significant bits (bit 0 and up) contain padding '0's.
    ///
    /// Note: Default value per GESC#113.
    POLYNOMIAL OFFSET(0) NUMBITS(31) []
],
TRNG_MON_CTL [
    /// Selection of the bitstream
    BITSTREAM_SEL OFFSET(0) NUMBITS(2) [
        DAS = 0,
        RED = 1,
        TR = 2,
        UNDEFINED = 3
    ],
    /// Adaptive proportion (AP) test enable:
    /// '0': Disabled.
    /// '1': Enabled.
    ///
    /// On a AP detection, HW sets this field to '0' and sets INTR_ERROR.TRNG_AP_DETECT to '1.
    AP OFFSET(8) NUMBITS(1) [],
    /// Repetition count (RC) test enable:
    /// '0': Disabled.
    /// '1': Enabled.
    ///
    /// On a RC detection, HW sets this field to '0' and sets INTR_ERROR.TRNG_RC_DETECT to '1.
    RC OFFSET(9) NUMBITS(1) []
],
TRNG_MON_RC_CTL [
    /// Cutoff count (legal range is [1, 255]):
    /// '0': Illegal.
    /// '1': 1 repetition.
    /// ...
    /// '255': 255 repetitions.
    CUTOFF_COUNT8 OFFSET(0) NUMBITS(8) []
],
TRNG_MON_RC_STATUS0 [
    /// Current active bit value:
    /// '0': '0'.
    /// '1': '1'.
    ///
    /// This field is only valid when TRNG_MON_RC_STATUS1.REP_COUNT is NOT equal to '0'.
    BIT OFFSET(0) NUMBITS(1) []
],
TRNG_MON_RC_STATUS1 [
    /// Number of repetitions of the current active bit counter:
    /// '0': 0 repetitions.
    /// ...
    /// '255': 255 repetitions.
    REP_COUNT OFFSET(0) NUMBITS(8) []
],
TRNG_MON_AP_CTL [
    /// Cutoff count (legal range is [1, 65535]).
    /// '0': Illegal.
    /// '1': 1 occurrence.
    /// ...
    /// '65535': 65535 occurrences.
    CUTOFF_COUNT16 OFFSET(0) NUMBITS(16) [],
    /// Window size (minus 1) :
    /// '0': 1 bit.
    /// ...
    /// '65535': 65536 bits.
    WINDOW_SIZE OFFSET(16) NUMBITS(16) []
],
TRNG_MON_AP_STATUS0 [
    /// Current active bit value:
    /// '0': '0'.
    /// '1': '1'.
    ///
    /// This field is only valid when TRNG_MON_AP_STATUS1.OCC_COUNT is NOT equal to '0'.
    BIT OFFSET(0) NUMBITS(1) []
],
TRNG_MON_AP_STATUS1 [
    /// Number of occurrences of the current active bit counter:
    /// '0': 0 occurrences
    /// ...
    /// '65535': 65535 occurrences
    OCC_COUNT OFFSET(0) NUMBITS(16) [],
    /// Counter to keep track of the current index in the window (counts from '0' to TRNG_MON_AP_CTL.WINDOW_SIZE to '0').
    WINDOW_INDEX OFFSET(16) NUMBITS(16) []
],
INTR_TRNG [
    /// This interrupt cause is activated (HW sets the field to '1') when the TRNG is initialized.
    INITIALIZED OFFSET(0) NUMBITS(1) [],
    /// This interrupt cause is activated (HW sets the field to '1') when 32 bits of TRNG data becomes available in TRNG_RESULT.
    DATA_AVAILABLE OFFSET(1) NUMBITS(1) [],
    /// This interrupt cause is activated (HW sets the field to '1') when the TRNG monitor detects an 'adaptive proportion' error.
    AP_DETECT OFFSET(2) NUMBITS(1) [],
    /// This interrupt cause is activated (HW sets the field to '1') when the TRNG monitor detects an 'repetition count' error.
    RC_DETECT OFFSET(3) NUMBITS(1) []
],
INTR_TRNG_SET [
    /// SW writes a '1' to this field to set the corresponding field in interrupt request register.
    INITIALIZED OFFSET(0) NUMBITS(1) [],
    /// SW writes a '1' to this field to set the corresponding field in interrupt request register.
    DATA_AVAILABLE OFFSET(1) NUMBITS(1) [],
    /// SW writes a '1' to this field to set the corresponding field in interrupt request register.
    AP_DETECT OFFSET(2) NUMBITS(1) [],
    /// SW writes a '1' to this field to set the corresponding field in interrupt request register.
    RC_DETECT OFFSET(3) NUMBITS(1) []
],
INTR_TRNG_MASK [
    /// Mask bit for corresponding field in interrupt request register.
    INITIALIZED OFFSET(0) NUMBITS(1) [],
    /// Mask bit for corresponding field in interrupt request register.
    DATA_AVAILABLE OFFSET(1) NUMBITS(1) [],
    /// Mask bit for corresponding field in interrupt request register.
    AP_DETECT OFFSET(2) NUMBITS(1) [],
    /// Mask bit for corresponding field in interrupt request register.
    RC_DETECT OFFSET(3) NUMBITS(1) []
],
INTR_TRNG_MASKED [
    /// Logical and of corresponding request and mask bits.
    INITIALIZED OFFSET(0) NUMBITS(1) [],
    /// Logical and of corresponding request and mask bits.
    DATA_AVAILABLE OFFSET(1) NUMBITS(1) [],
    /// Logical and of corresponding request and mask bits.
    AP_DETECT OFFSET(2) NUMBITS(1) [],
    /// Logical and of corresponding request and mask bits.
    RC_DETECT OFFSET(3) NUMBITS(1) []
]
];
const BASE_ADDR: u32 = 0x4223_0000;
const POLY_MASK: u32 = 0x7fff_ffff;
const DEFAULT_GARO31_POLY: u32 = 0xb2d1_ab70;
const DEFAULT_FIRO31_POLY: u32 = 0xe6b8_c3b3;

// SAFETY: BASE_ADDR is the valid memory-mapped base address for Cryptolite
// registers.
const CRYPTOLITE_BASE: StaticRef<CryptoliteRegisters> =
    unsafe { StaticRef::new(BASE_ADDR as *const CryptoliteRegisters) };

pub struct Cryptolite {
    registers: StaticRef<CryptoliteRegisters>,
}

impl Cryptolite {
    pub const fn new() -> Self {
        Self {
            registers: CRYPTOLITE_BASE,
        }
    }
}

impl Default for Cryptolite {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoliteErr {
    BadParams = 0x01,
    HwBusy = 0x02,
    BusError = 0x03,
    NotSupported = 0x04,
    SizeNotX16 = 0x05,
    AlignmentError = 0x06,
    TrngNotEnabled = 0x07,
    TrngUnhealthy = 0x08,
    BufferNotAligned = 0x09,
    HwError = 0x0a,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrngRoSelect {
    Ro11 = 0,
    Ro15 = 1,
    Garo15 = 2,
    Garo31 = 3,
    Firo15 = 4,
    Firo31 = 5,
}

pub type TrngBitstreamSelect = TRNG_MON_CTL::BITSTREAM_SEL::Value;

#[expect(
    clippy::struct_excessive_bools,
    reason = "TrngConfig has multiple independent boolean options for hardware control"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrngConfig {
    pub sample_clock_div: u8,
    pub reduced_clock_div: u8,
    pub init_delay: u8,
    pub vn_corrector_enable: bool,
    pub enable_ap_test: bool,
    pub enable_rc_test: bool,
    pub stop_on_ap_detect: bool,
    pub stop_on_rc_detect: bool,
    pub garo31_poly: u32,
    pub firo31_poly: u32,
    pub mon_bitstream_select: TrngBitstreamSelect,
    pub mon_cutoff_count8: u8,
    pub mon_cutoff_count16: u16,
    pub mon_window_size: u16,
}

impl Default for TrngConfig {
    fn default() -> Self {
        Self {
            sample_clock_div: 1,
            reduced_clock_div: 3,
            init_delay: 255,
            vn_corrector_enable: true,
            enable_ap_test: true,
            enable_rc_test: true,
            stop_on_ap_detect: true,
            stop_on_rc_detect: true,
            garo31_poly: DEFAULT_GARO31_POLY,
            firo31_poly: DEFAULT_FIRO31_POLY,
            mon_bitstream_select: TrngBitstreamSelect::TR,
            mon_cutoff_count8: 255,
            mon_cutoff_count16: 255,
            mon_window_size: 255,
        }
    }
}

impl Cryptolite {
    fn trng_mon_clear_health_status(&self) {
        self.registers
            .intr_trng
            .write(INTR_TRNG::AP_DETECT::SET + INTR_TRNG::RC_DETECT::SET);
    }

    fn trng_wait_for_init(&self) {
        while !self.registers.intr_trng.is_set(INTR_TRNG::INITIALIZED) {
            core::hint::spin_loop();
        }
    }

    fn trng_wait_for_complete(&self) {
        while !self.registers.intr_trng.is_set(INTR_TRNG::DATA_AVAILABLE)
            && !self.registers.intr_trng.is_set(INTR_TRNG::AP_DETECT)
            && !self.registers.intr_trng.is_set(INTR_TRNG::RC_DETECT)
        {
            core::hint::spin_loop();
        }
    }

    fn trng_mon_get_health_status(&self) -> u8 {
        u8::from(self.registers.intr_trng.is_set(INTR_TRNG::AP_DETECT))
            | (u8::from(self.registers.intr_trng.is_set(INTR_TRNG::RC_DETECT)) << 1)
    }

    fn trng_mon_set_bitstream_selector(
        &self,
        bitstream_selector: TrngBitstreamSelect,
    ) -> Result<(), CryptoliteErr> {
        if bitstream_selector == TrngBitstreamSelect::UNDEFINED {
            return Err(CryptoliteErr::BadParams);
        }

        self.registers
            .trng_mon_ctl
            .modify(TRNG_MON_CTL::BITSTREAM_SEL.val(bitstream_selector as u32));
        Ok(())
    }

    fn trng_mon_enable_ap_test(&self) {
        self.registers.trng_mon_ctl.modify(TRNG_MON_CTL::AP::SET);
    }

    fn trng_mon_enable_rc_test(&self) {
        self.registers.trng_mon_ctl.modify(TRNG_MON_CTL::RC::SET);
    }

    /// Configure TRNG control and monitor registers.
    pub fn trng_init(&self, config: &TrngConfig) -> Result<(), CryptoliteErr> {
        if config.mon_bitstream_select == TrngBitstreamSelect::UNDEFINED {
            return Err(CryptoliteErr::BadParams);
        }

        self.registers
            .intr_trng
            .write(INTR_TRNG::DATA_AVAILABLE::SET + INTR_TRNG::INITIALIZED::SET);
        self.trng_mon_clear_health_status();

        self.registers
            .trng_garo_ctl
            .write(TRNG_GARO_CTL::POLYNOMIAL.val(config.garo31_poly & POLY_MASK));
        self.registers
            .trng_firo_ctl
            .write(TRNG_FIRO_CTL::POLYNOMIAL.val(config.firo31_poly & POLY_MASK));

        self.registers.trng_ctl0.write(
            TRNG_CTL0::SAMPLE_CLOCK_DIV.val(u32::from(config.sample_clock_div))
                + TRNG_CTL0::RED_CLOCK_DIV.val(u32::from(config.reduced_clock_div))
                + TRNG_CTL0::INIT_DELAY.val(u32::from(config.init_delay))
                + TRNG_CTL0::VON_NEUMANN_CORR.val(u32::from(config.vn_corrector_enable))
                + TRNG_CTL0::STOP_ON_AP_DETECT.val(u32::from(config.stop_on_ap_detect))
                + TRNG_CTL0::STOP_ON_RC_DETECT.val(u32::from(config.stop_on_rc_detect)),
        );

        self.trng_mon_set_bitstream_selector(config.mon_bitstream_select)?;

        if config.enable_ap_test {
            self.trng_mon_enable_ap_test();
        }
        if config.enable_rc_test {
            self.trng_mon_enable_rc_test();
        }

        self.registers
            .trng_mon_rc_ctl
            .write(TRNG_MON_RC_CTL::CUTOFF_COUNT8.val(u32::from(config.mon_cutoff_count8)));

        self.registers.trng_mon_ap_ctl.write(
            TRNG_MON_AP_CTL::CUTOFF_COUNT16.val(u32::from(config.mon_cutoff_count16))
                + TRNG_MON_AP_CTL::WINDOW_SIZE.val(u32::from(config.mon_window_size)),
        );

        Ok(())
    }

    pub fn trng_deinit(&self) {
        self.registers.trng_ctl0.write(TRNG_CTL0::INIT_DELAY.val(3));
        self.registers.trng_ctl1.write(
            TRNG_CTL1::RO11_EN::CLEAR
                + TRNG_CTL1::RO15_EN::CLEAR
                + TRNG_CTL1::GARO15_EN::CLEAR
                + TRNG_CTL1::GARO31_EN::CLEAR
                + TRNG_CTL1::FIRO15_EN::CLEAR
                + TRNG_CTL1::FIRO31_EN::CLEAR,
        );
        self.registers
            .trng_garo_ctl
            .write(TRNG_GARO_CTL::POLYNOMIAL.val(0));
        self.registers
            .trng_firo_ctl
            .write(TRNG_FIRO_CTL::POLYNOMIAL.val(0));
        self.registers
            .trng_mon_ctl
            .write(TRNG_MON_CTL::BITSTREAM_SEL.val(TrngBitstreamSelect::TR as u32));
        self.registers
            .trng_mon_rc_ctl
            .write(TRNG_MON_RC_CTL::CUTOFF_COUNT8.val(0));
        self.registers
            .trng_mon_ap_ctl
            .write(TRNG_MON_AP_CTL::CUTOFF_COUNT16.val(0) + TRNG_MON_AP_CTL::WINDOW_SIZE.val(0));
        self.registers
            .intr_trng
            .write(INTR_TRNG::DATA_AVAILABLE::SET + INTR_TRNG::INITIALIZED::SET);
        self.trng_mon_clear_health_status();
    }

    pub fn trng_is_enabled(&self) -> bool {
        self.registers.trng_ctl1.is_set(TRNG_CTL1::RO11_EN)
            || self.registers.trng_ctl1.is_set(TRNG_CTL1::RO15_EN)
            || self.registers.trng_ctl1.is_set(TRNG_CTL1::GARO15_EN)
            || self.registers.trng_ctl1.is_set(TRNG_CTL1::GARO31_EN)
            || self.registers.trng_ctl1.is_set(TRNG_CTL1::FIRO15_EN)
            || self.registers.trng_ctl1.is_set(TRNG_CTL1::FIRO31_EN)
    }

    /// Enable all TRNG ring oscillators and wait for initialization.
    pub fn trng_enable(&self) -> Result<(), CryptoliteErr> {
        if self.trng_is_enabled() {
            return Ok(());
        }
        self.registers
            .intr_trng
            .write(INTR_TRNG::DATA_AVAILABLE::SET + INTR_TRNG::INITIALIZED::SET);
        self.registers.trng_ctl1.write(
            TRNG_CTL1::RO11_EN::SET
                + TRNG_CTL1::RO15_EN::SET
                + TRNG_CTL1::GARO15_EN::SET
                + TRNG_CTL1::GARO31_EN::SET
                + TRNG_CTL1::FIRO15_EN::SET
                + TRNG_CTL1::FIRO31_EN::SET,
        );
        self.trng_wait_for_init();
        Ok(())
    }

    /// Disable all TRNG ring oscillators.
    pub fn trng_disable(&self) -> Result<(), CryptoliteErr> {
        if self.trng_is_enabled() {
            self.registers
                .intr_trng
                .write(INTR_TRNG::DATA_AVAILABLE::SET + INTR_TRNG::INITIALIZED::SET);
            self.registers.trng_ctl1.write(
                TRNG_CTL1::RO11_EN::CLEAR
                    + TRNG_CTL1::RO15_EN::CLEAR
                    + TRNG_CTL1::GARO15_EN::CLEAR
                    + TRNG_CTL1::GARO31_EN::CLEAR
                    + TRNG_CTL1::FIRO15_EN::CLEAR
                    + TRNG_CTL1::FIRO31_EN::CLEAR,
            );
        }

        Ok(())
    }

    /// Read one 32-bit random value.
    ///
    /// Returns `Err(CryptoliteErr::TrngNotEnabled)` if TRNG is disabled and
    /// `Err(CryptoliteErr::TrngUnhealthy)` when health checks report an error.
    pub fn trng_read_data(&self) -> Result<u32, CryptoliteErr> {
        if !self.trng_is_enabled() {
            return Err(CryptoliteErr::TrngNotEnabled);
        }

        self.trng_wait_for_complete();
        let random_data = self.registers.trng_result.read(TRNG_RESULT::DATA);

        if self.trng_mon_get_health_status() != 0 {
            Err(CryptoliteErr::TrngUnhealthy)
        } else {
            Ok(random_data)
        }
    }

    pub fn trng_try_fill_bytes(&self, dest: &mut [u8]) -> Result<(), CryptoliteErr> {
        if !self.trng_is_enabled() {
            return Err(CryptoliteErr::TrngNotEnabled);
        }
        let mut offset = 0;
        while offset < dest.len() {
            let word = self.trng_read_data()?;
            let bytes = word.to_le_bytes();
            let remaining = dest.len() - offset;
            let take = core::cmp::min(remaining, bytes.len());
            dest[offset..offset + take].copy_from_slice(&bytes[..take]);
            offset += take;
        }

        Ok(())
    }
}
