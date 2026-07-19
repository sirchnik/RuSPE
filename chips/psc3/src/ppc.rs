use helpers::static_ref::StaticRef;
use tock_registers::fields::FieldValue;
use tock_registers::interfaces::{Readable as _, Writeable as _};
use tock_registers::registers::{ReadOnly, ReadWrite};
use tock_registers::{register_bitfields, register_structs};

register_structs! {
    /// Peripheral Protection Controller
    PpcRegisters {
        /// PPC Control Registers
        (0x000 => ppc_ctl: ReadWrite<u32, PPC_CTL::Register>),
        (0x004 => _reserved0),
        /// Locked Mask
        ///
        /// A mask that indicates which protection contexts have access to a peripheral region.  Bit i specifies the access for protection context i.
        /// 0: The protection context has no access to this region.
        /// 1: The protection context has access to this region, subject to secure and privilege attribute constraints setup in PPC_NS_ATT, PPC_S_P_ATT, PPC_NS_P_ATT registers)
        (0x00C => ppc_lock_mask: ReadWrite<u32>),
        (0x010 => _reserved1),
        /// Protection Context Mask
        (0x1000 => ppc_pc_masks: [ReadWrite<u32>; 1024]),
        /// Non-secure attribute
        ///
        /// Each bit indicates whether access to a peripheral region must be secure or non-secure:
        /// IF SECURITY_AWARE=0
        /// 0 - allow only secure access to respective peripheral region.
        /// 1 - allow only non-secure access to respective peripheral region.
        /// IF SECURITY_AWARE=1
        /// 0 - allow only secure access to respective peripheral region.
        /// 1 - allows both secure and non-secure access to respective peripheral region.
        /// (Note that, depending on this setting the privilege access requirement for this region is specified in the corresponding PPC_S_P_ATT or PPC_NS_P_ATT register)
        (0x2000 => ppc_ns_attrs: [ReadWrite<u32>; 32]),
        (0x2080 => _reserved2),
        /// Secure Privilege Attribute
        ///
        /// Each bit indicates whether access to a secure peripheral region requires privilege:
        /// 0 - allow only secure privileged access to respective peripheral region.
        /// 1 - allow only secure unprivileged or privileged access to respective peripheral region.
        (0x2400 => ppc_s_p_attrs: [ReadWrite<u32>; 32]),
        (0x2480 => _reserved3),
        /// Non-secure Privilege Attribute
        ///
        ///  Each bit indicates whether access to a non-secure peripheral region requires privilege:
        /// 0 - allow only non-secure privileged access to respective peripheral region.
        /// 1 - allow only non-secure unprivileged or privileged access to respective peripheral region.
        (0x4000 => ppc_ns_p_attrs: [ReadWrite<u32>; 32]),
        (0x4080 => _reserved4),
        /// Region Address
        (0x5000 => regions_addr: [ReadOnly<u32>; 222]),
        (0x5378 => _reserved5),
        /// Region Attribute
        (0x6000 => regions_attr: [ReadOnly<u32, REGION_ATTR::Register>; 222]),
        (0x6378 => @END),
    }
}
register_bitfields![u32,
pub PPC_CTL [
    /// Response Configuration. This field configures the security violation response.
    RESP_CFG OFFSET(0) NUMBITS(1) [
        // Read-Zero, Write-Ignore
        RZWI = 0,
        BUS_ERROR = 1
    ]
],
REGION_ATTR [
    /// This field specifies the size of the peripheral region.
    R_SIZE OFFSET(24) NUMBITS(5) [
        UNDEFINED = 0,
        SIZE_4B = 1,
        SIZE_8B = 2,
        SIZE_16B = 3,
        SIZE_32B = 4,
        SIZE_64B = 5,
        SIZE_128B = 6,
        SIZE_256B = 7,
        SIZE_512B = 8,
        SIZE_1KB = 9,
        SIZE_2KB = 10,
        SIZE_4KB = 11,
        SIZE_8KB = 12,
        SIZE_16KB = 13,
        SIZE_32KB = 14,
        SIZE_64KB = 15,
        SIZE_128KB = 16,
        SIZE_256KB = 17,
        SIZE_512KB = 18,
        SIZE_1MB = 19,
        SIZE_2MB = 20,
        SIZE_4MB = 21,
        SIZE_8MB = 22,
        SIZE_16MB = 23,
        SIZE_32MB = 24,
        SIZE_64MB = 25,
        SIZE_128MB = 26,
        SIZE_256MB = 27,
        SIZE_512MB = 28,
        SIZE_1GB = 29,
        SIZE_2GB = 30,
        SIZE_4GB = 31
    ]
],
];
const PPC_BASE: StaticRef<PpcRegisters> =
    unsafe { StaticRef::new(0x52020000 as *const PpcRegisters) };

/// PPC region definitions
/// Pfrom architecture reference manual
#[derive(Clone, Copy)]
#[repr(u16)]
pub enum PpcRegion {
    ProtPeri0Main = 0,                  // Address 0x42000000, size 0x00004000
    ProtPeri0Gr0Group = 1,              // Address 0x42004010, size 0x00000008
    ProtPeri0Gr1Group = 2,              // Address 0x42004040, size 0x00000020
    ProtPeri0Gr2Group = 3,              // Address 0x42004080, size 0x00000020
    ProtPeri0Gr3Group = 4,              // Address 0x420040c0, size 0x00000020
    ProtPeri0Gr4Group = 5,              // Address 0x42004100, size 0x00000020
    ProtPeri0Gr5Group = 6,              // Address 0x42004150, size 0x00000008
    ProtPeri0Gr0Boot = 7,               // Address 0x42004020, size 0x00000004
    ProtPeri0Gr1Boot = 8,               // Address 0x42004060, size 0x00000004
    ProtPeri0Gr2Boot = 9,               // Address 0x420040a0, size 0x00000004
    ProtPeri0Gr3Boot = 10,              // Address 0x420040e0, size 0x00000004
    ProtPeri0Gr4Boot = 11,              // Address 0x42004120, size 0x00000004
    ProtPeri0Gr5Boot = 12,              // Address 0x42004160, size 0x00000004
    ProtPeri0Tr = 13,                   // Address 0x42008000, size 0x00008000
    ProtPpc0PpcPpcSecure = 14,          // Address 0x42020000, size 0x00004000
    ProtPpc0PpcPpcNonsecure = 15,       // Address 0x42024000, size 0x00004000
    ProtPeriPclk0Main = 16,             // Address 0x42040000, size 0x00010000
    ProtCpuss = 17,                     // Address 0x42100000, size 0x00010000
    ProtRamc0Cm33 = 18,                 // Address 0x42110000, size 0x00000040
    ProtRamc0Boot = 19,                 // Address 0x42110100, size 0x00000008
    ProtRamc0RamPwr = 20,               // Address 0x42110200, size 0x00000100
    ProtRamc0Mpc0PpcMpcMain = 21,       // Address 0x42114000, size 0x00000004
    ProtRamc0Mpc0PpcMpcPc = 22,         // Address 0x42114100, size 0x00000020
    ProtRamc0Mpc0PpcMpcRot = 23,        // Address 0x42114200, size 0x00000020
    ProtPromcCm33 = 24,                 // Address 0x42140000, size 0x00000004
    ProtPromcMpc0PpcMpcMain = 25,       // Address 0x42141000, size 0x00000004
    ProtPromcMpc0PpcMpcPc = 26,         // Address 0x42141100, size 0x00000020
    ProtPromcMpc0PpcMpcRot = 27,        // Address 0x42141200, size 0x00000020
    ProtFlashcBoot = 28,                // Address 0x42150000, size 0x00000008
    ProtFlashcBoot1 = 29,               // Address 0x42150100, size 0x00000020
    ProtFlashcMain = 30,                // Address 0x42150200, size 0x00000010
    ProtFlashcDft = 31,                 // Address 0x42150400, size 0x00000080
    ProtFlashcEcc = 32,                 // Address 0x42150800, size 0x00000010
    ProtFlashcMpc0PpcMpcMain = 33,      // Address 0x42151000, size 0x00000004
    ProtFlashcMpc0PpcMpcPc = 34,        // Address 0x42151100, size 0x00000020
    ProtFlashcMpc0PpcMpcRot = 35,       // Address 0x42151200, size 0x00000020
    ProtFlashcFmCtlFmDft = 36,          // Address 0x42152000, size 0x00000004
    ProtFlashcFmCtlFmBoot = 37,         // Address 0x42152040, size 0x00000008
    ProtFlashcFmCtlFmMain = 38,         // Address 0x42152800, size 0x00000800
    ProtMxcm33Cm33 = 39,                // Address 0x42160000, size 0x00000100
    ProtMxcm33Cm33S = 40,               // Address 0x42161000, size 0x00000004
    ProtMxcm33Cm33Ns = 41,              // Address 0x42161004, size 0x00000004
    ProtMxcm33BootPc0 = 42,             // Address 0x42162000, size 0x00000080
    ProtMxcm33BootPc1 = 43,             // Address 0x42162100, size 0x00000004
    ProtMxcm33BootPc2 = 44,             // Address 0x42162140, size 0x00000004
    ProtMxcm33BootPc3 = 45,             // Address 0x42162180, size 0x00000004
    ProtMxcm33Boot = 46,                // Address 0x421621c0, size 0x00000004
    ProtMxcm33Cm33Int = 47,             // Address 0x42168000, size 0x00000400
    ProtDw0Dw = 48,                     // Address 0x42180000, size 0x00000080
    ProtDw1Dw = 49,                     // Address 0x42190000, size 0x00000080
    ProtDw0DwCrc = 50,                  // Address 0x42180100, size 0x00000080
    ProtDw1DwCrc = 51,                  // Address 0x42190100, size 0x00000080
    ProtDw0ChStruct0Ch = 52,            // Address 0x42188000, size 0x00000040
    ProtDw0ChStruct1Ch = 53,            // Address 0x42188040, size 0x00000040
    ProtDw0ChStruct2Ch = 54,            // Address 0x42188080, size 0x00000040
    ProtDw0ChStruct3Ch = 55,            // Address 0x421880c0, size 0x00000040
    ProtDw0ChStruct4Ch = 56,            // Address 0x42188100, size 0x00000040
    ProtDw0ChStruct5Ch = 57,            // Address 0x42188140, size 0x00000040
    ProtDw0ChStruct6Ch = 58,            // Address 0x42188180, size 0x00000040
    ProtDw0ChStruct7Ch = 59,            // Address 0x421881c0, size 0x00000040
    ProtDw0ChStruct8Ch = 60,            // Address 0x42188200, size 0x00000040
    ProtDw0ChStruct9Ch = 61,            // Address 0x42188240, size 0x00000040
    ProtDw0ChStruct10Ch = 62,           // Address 0x42188280, size 0x00000040
    ProtDw0ChStruct11Ch = 63,           // Address 0x421882c0, size 0x00000040
    ProtDw0ChStruct12Ch = 64,           // Address 0x42188300, size 0x00000040
    ProtDw0ChStruct13Ch = 65,           // Address 0x42188340, size 0x00000040
    ProtDw0ChStruct14Ch = 66,           // Address 0x42188380, size 0x00000040
    ProtDw0ChStruct15Ch = 67,           // Address 0x421883c0, size 0x00000040
    ProtDw1ChStruct0Ch = 68,            // Address 0x42198000, size 0x00000040
    ProtDw1ChStruct1Ch = 69,            // Address 0x42198040, size 0x00000040
    ProtDw1ChStruct2Ch = 70,            // Address 0x42198080, size 0x00000040
    ProtDw1ChStruct3Ch = 71,            // Address 0x421980c0, size 0x00000040
    ProtDw1ChStruct4Ch = 72,            // Address 0x42198100, size 0x00000040
    ProtDw1ChStruct5Ch = 73,            // Address 0x42198140, size 0x00000040
    ProtDw1ChStruct6Ch = 74,            // Address 0x42198180, size 0x00000040
    ProtDw1ChStruct7Ch = 75,            // Address 0x421981c0, size 0x00000040
    ProtDw1ChStruct8Ch = 76,            // Address 0x42198200, size 0x00000040
    ProtDw1ChStruct9Ch = 77,            // Address 0x42198240, size 0x00000040
    ProtDw1ChStruct10Ch = 78,           // Address 0x42198280, size 0x00000040
    ProtDw1ChStruct11Ch = 79,           // Address 0x421982c0, size 0x00000040
    ProtDw1ChStruct12Ch = 80,           // Address 0x42198300, size 0x00000040
    ProtDw1ChStruct13Ch = 81,           // Address 0x42198340, size 0x00000040
    ProtDw1ChStruct14Ch = 82,           // Address 0x42198380, size 0x00000040
    ProtDw1ChStruct15Ch = 83,           // Address 0x421983c0, size 0x00000040
    ProtCpussAllPc = 84,                // Address 0x421c0000, size 0x00000080
    ProtCpussDdft = 85,                 // Address 0x421c0080, size 0x00000004
    ProtCpussCm33S = 86,                // Address 0x421c0100, size 0x00000004
    ProtCpussCm33Ns = 87,               // Address 0x421c0120, size 0x00000004
    ProtCpussMscInt = 88,               // Address 0x421c0200, size 0x00000010
    ProtCpussAp = 89,                   // Address 0x421c1000, size 0x00000004
    ProtCpussBoot = 90,                 // Address 0x421c2000, size 0x00000008
    ProtMs0Main = 91,                   // Address 0x421c4000, size 0x00000004
    ProtMs4Main = 92,                   // Address 0x421c4040, size 0x00000004
    ProtMs5Main = 93,                   // Address 0x421c4050, size 0x00000004
    ProtMs7Main = 94,                   // Address 0x421c4070, size 0x00000004
    ProtMs31Main = 95,                  // Address 0x421c41f0, size 0x00000004
    ProtMsPc0Priv = 96,                 // Address 0x421c5000, size 0x00000004
    ProtMsPc31Priv = 97,                // Address 0x421c51f0, size 0x00000004
    ProtMsPc0PrivMir = 98,              // Address 0x421c5004, size 0x00000004
    ProtMsPc31PrivMir = 99,             // Address 0x421c51f4, size 0x00000004
    ProtMscAcg = 100,                   // Address 0x421c6000, size 0x00000040
    ProtCpussSlCtlGroup = 101,          // Address 0x421c8000, size 0x00000008
    ProtIpcStruct0Ipc = 102,            // Address 0x421d0000, size 0x00000020
    ProtIpcStruct1Ipc = 103,            // Address 0x421d0020, size 0x00000020
    ProtIpcStruct2Ipc = 104,            // Address 0x421d0040, size 0x00000020
    ProtIpcStruct3Ipc = 105,            // Address 0x421d0060, size 0x00000020
    ProtIpcIntrStruct0Intr = 106,       // Address 0x421d1000, size 0x00000010
    ProtIpcIntrStruct1Intr = 107,       // Address 0x421d1020, size 0x00000010
    ProtFaultStruct0Main = 108,         // Address 0x421e0000, size 0x00000100
    ProtSrssGeneral = 109,              // Address 0x42200000, size 0x00000400
    ProtSrssGeneral2 = 110,             // Address 0x42200400, size 0x00000040
    ProtSrssHibData = 111,              // Address 0x422008a0, size 0x00000010
    ProtSrssMain = 112,                 // Address 0x42201000, size 0x00001000
    ProtSrssSecure = 113,               // Address 0x42202000, size 0x00002000
    ProtRamTrimSrssSram = 114,          // Address 0x42204000, size 0x00000008
    ProtSrssDpll = 115,                 // Address 0x42204200, size 0x00000040
    ProtSrssWdt = 116,                  // Address 0x4220c000, size 0x00000010
    ProtMain = 117,                     // Address 0x4220d000, size 0x00000040
    ProtPwrmodePwrmode = 118,           // Address 0x42210000, size 0x00004000
    ProtBackupBackup = 119,             // Address 0x42220000, size 0x00000100
    ProtBackupBBreg0 = 120,             // Address 0x42221000, size 0x00000010
    ProtBackupBBreg1 = 121,             // Address 0x42221010, size 0x00000010
    ProtBackupBBreg2 = 122,             // Address 0x42221020, size 0x00000020
    ProtBackupBBreg3 = 123,             // Address 0x42221080, size 0x00000040
    ProtBackupBackupSecure = 124,       // Address 0x4222ff00, size 0x00000004
    ProtCryptoliteMain = 125,           // Address 0x42230000, size 0x00000100
    ProtCryptoliteTrng = 126,           // Address 0x42230100, size 0x00000100
    ProtMxcordic10 = 127,               // Address 0x42240000, size 0x00010000
    ProtDebug600Debug600 = 128,         // Address 0x42250000, size 0x00000004
    ProtHsiomPrt0Prt = 129,             // Address 0x42400000, size 0x00000008
    ProtHsiomPrt1Prt = 130,             // Address 0x42400010, size 0x00000008
    ProtHsiomPrt2Prt = 131,             // Address 0x42400020, size 0x00000008
    ProtHsiomPrt3Prt = 132,             // Address 0x42400030, size 0x00000008
    ProtHsiomPrt4Prt = 133,             // Address 0x42400040, size 0x00000008
    ProtHsiomPrt5Prt = 134,             // Address 0x42400050, size 0x00000008
    ProtHsiomPrt6Prt = 135,             // Address 0x42400060, size 0x00000008
    ProtHsiomPrt7Prt = 136,             // Address 0x42400070, size 0x00000008
    ProtHsiomPrt8Prt = 137,             // Address 0x42400080, size 0x00000008
    ProtHsiomPrt9Prt = 138,             // Address 0x42400090, size 0x00000008
    ProtHsiomSecurePrt0SecurePrt = 139, // Address 0x42401000, size 0x00000004
    ProtHsiomSecurePrt1SecurePrt = 140, // Address 0x42401010, size 0x00000004
    ProtHsiomSecurePrt2SecurePrt = 141, // Address 0x42401020, size 0x00000004
    ProtHsiomSecurePrt3SecurePrt = 142, // Address 0x42401030, size 0x00000004
    ProtHsiomSecurePrt4SecurePrt = 143, // Address 0x42401040, size 0x00000004
    ProtHsiomSecurePrt5SecurePrt = 144, // Address 0x42401050, size 0x00000004
    ProtHsiomSecurePrt6SecurePrt = 145, // Address 0x42401060, size 0x00000004
    ProtHsiomSecurePrt7SecurePrt = 146, // Address 0x42401070, size 0x00000004
    ProtHsiomSecurePrt8SecurePrt = 147, // Address 0x42401080, size 0x00000004
    ProtHsiomSecurePrt9SecurePrt = 148, // Address 0x42401090, size 0x00000004
    ProtHsiomAmux = 149,                // Address 0x42402000, size 0x00000010
    ProtHsiomMon = 150,                 // Address 0x42402200, size 0x00000010
    ProtGpioPrt0Prt = 151,              // Address 0x42410000, size 0x00000040
    ProtGpioPrt1Prt = 152,              // Address 0x42410080, size 0x00000040
    ProtGpioPrt2Prt = 153,              // Address 0x42410100, size 0x00000040
    ProtGpioPrt3Prt = 154,              // Address 0x42410180, size 0x00000040
    ProtGpioPrt4Prt = 155,              // Address 0x42410200, size 0x00000040
    ProtGpioPrt5Prt = 156,              // Address 0x42410280, size 0x00000040
    ProtGpioPrt6Prt = 157,              // Address 0x42410300, size 0x00000040
    ProtGpioPrt7Prt = 158,              // Address 0x42410380, size 0x00000040
    ProtGpioPrt8Prt = 159,              // Address 0x42410400, size 0x00000040
    ProtGpioPrt9Prt = 160,              // Address 0x42410480, size 0x00000040
    ProtGpioPrt0Cfg = 161,              // Address 0x42410040, size 0x00000040
    ProtGpioPrt1Cfg = 162,              // Address 0x424100c0, size 0x00000040
    ProtGpioPrt2Cfg = 163,              // Address 0x42410140, size 0x00000040
    ProtGpioPrt3Cfg = 164,              // Address 0x424101c0, size 0x00000040
    ProtGpioPrt4Cfg = 165,              // Address 0x42410240, size 0x00000040
    ProtGpioPrt5Cfg = 166,              // Address 0x424102c0, size 0x00000040
    ProtGpioPrt6Cfg = 167,              // Address 0x42410340, size 0x00000040
    ProtGpioPrt7Cfg = 168,              // Address 0x424103c0, size 0x00000040
    ProtGpioPrt8Cfg = 169,              // Address 0x42410440, size 0x00000040
    ProtGpioPrt9Cfg = 170,              // Address 0x424104c0, size 0x00000040
    ProtGpioSecGpio = 171,              // Address 0x42417000, size 0x00000004
    ProtGpioGpio = 172,                 // Address 0x42418000, size 0x00000040
    ProtGpioTest = 173,                 // Address 0x42419000, size 0x00000008
    ProtSmartioPrt0Prt = 174,           // Address 0x42420000, size 0x00000100
    ProtSmartioPrt1Prt = 175,           // Address 0x42420100, size 0x00000100
    ProtSmartioPrt2Prt = 176,           // Address 0x42420200, size 0x00000100
    ProtSmartioPrt3Prt = 177,           // Address 0x42420300, size 0x00000100
    ProtSmartioPrt5Prt = 178,           // Address 0x42420500, size 0x00000100
    ProtSmartioPrt6Prt = 179,           // Address 0x42420600, size 0x00000100
    ProtSmartioPrt9Prt = 180,           // Address 0x42420900, size 0x00000100
    ProtLpcomp = 181,                   // Address 0x42430000, size 0x00010000
    ProtDft = 182,                      // Address 0x42600000, size 0x00001000
    ProtEfuseCtl1 = 183,                // Address 0x42610000, size 0x00000004
    ProtEfuseCtl2 = 184,                // Address 0x42610100, size 0x00000080
    ProtEfuseCtl3 = 185,                // Address 0x42610180, size 0x00000004
    ProtEfuseDataBoot1 = 186,           // Address 0x42610800, size 0x00000080
    ProtCanfd0Ch0Ch = 187,              // Address 0x42800000, size 0x00000200
    ProtCanfd0Ch1Ch = 188,              // Address 0x42800200, size 0x00000200
    ProtCanfd0Main = 189,               // Address 0x42801000, size 0x00000040
    ProtCanfd0Buf = 190,                // Address 0x42810000, size 0x00010000
    ProtScb0 = 191,                     // Address 0x42820000, size 0x00010000
    ProtScb1 = 192,                     // Address 0x42840000, size 0x00010000
    ProtScb2 = 193,                     // Address 0x42850000, size 0x00010000
    ProtScb3 = 194,                     // Address 0x42860000, size 0x00010000
    ProtScb4 = 195,                     // Address 0x42870000, size 0x00010000
    ProtScb5 = 196,                     // Address 0x42c00000, size 0x00010000
    ProtTcpwm0Grp0Cnt0Cnt = 197,        // Address 0x42a00000, size 0x00000100
    ProtTcpwm0Grp0Cnt1Cnt = 198,        // Address 0x42a00100, size 0x00000100
    ProtTcpwm0Grp0Cnt2Cnt = 199,        // Address 0x42a00200, size 0x00000100
    ProtTcpwm0Grp0Cnt3Cnt = 200,        // Address 0x42a00300, size 0x00000100
    ProtTcpwm0Grp1Cnt0Cnt = 201,        // Address 0x42a10000, size 0x00000100
    ProtTcpwm0Grp1Cnt1Cnt = 202,        // Address 0x42a10100, size 0x00000100
    ProtTcpwm0Grp1Cnt2Cnt = 203,        // Address 0x42a10200, size 0x00000100
    ProtTcpwm0Grp1Cnt3Cnt = 204,        // Address 0x42a10300, size 0x00000100
    ProtTcpwm0Grp1Cnt4Cnt = 205,        // Address 0x42a10400, size 0x00000100
    ProtTcpwm0Grp1Cnt5Cnt = 206,        // Address 0x42a10500, size 0x00000100
    ProtTcpwm0Grp1Cnt6Cnt = 207,        // Address 0x42a10600, size 0x00000100
    ProtTcpwm0Grp1Cnt7Cnt = 208,        // Address 0x42a10700, size 0x00000100
    ProtTcpwm0Grp2Cnt0Cnt = 209,        // Address 0x42a20000, size 0x00000100
    ProtTcpwm0Grp2Cnt1Cnt = 210,        // Address 0x42a20100, size 0x00000100
    ProtTcpwm0Grp2Cnt2Cnt = 211,        // Address 0x42a20200, size 0x00000100
    ProtTcpwm0Grp2Cnt3Cnt = 212,        // Address 0x42a20300, size 0x00000100
    ProtTcpwm0Grp2Cnt4Cnt = 213,        // Address 0x42a20400, size 0x00000100
    ProtTcpwm0Grp2Cnt5Cnt = 214,        // Address 0x42a20500, size 0x00000100
    ProtTcpwm0Grp2Cnt6Cnt = 215,        // Address 0x42a20600, size 0x00000100
    ProtTcpwm0Grp2Cnt7Cnt = 216,        // Address 0x42a20700, size 0x00000100
    ProtTcpwm0TrAllGfTrAllGf = 217,     // Address 0x42a80000, size 0x00000040
    ProtTcpwm0TrAllSyncBypassTrAllSynBypass = 218, // Address 0x42a90000, size 0x00000004
    ProtTcpwm0Boot = 219,               // Address 0x42a90800, size 0x00000004
    ProtTcpwm0MotifGrp1Motif0Motif = 220, // Address 0x42aa4000, size 0x00000200
    ProtMcpass = 221,                   // Address 0x42b00000, size 0x00100000
}

/// Set access permissions for a given PPC region.
///
/// Parameters:
/// - `region`: The PPC region for which to set permissions.
/// - `allow_non_secure`: If true, allows non-secure (and secure) access to the
///   region.
/// - `allow_nsec_nonpriv`: If true, allows non-secure non-privileged (and
///   privileged) access to the region.
/// - `allow_sec_nonpriv`: If true, allows secure non-privileged (and
///   privileged) access to the region.
pub fn set_permissions(
    region: PpcRegion,
    allow_non_secure: bool,
    allow_nsec_nonpriv: bool,
    allow_sec_nonpriv: bool,
) {
    let region_index = region as usize;
    // 32 regions per 32-bit register
    let reg_index = region_index / 32;
    let bit_index = region_index % 32;

    assert!(reg_index < PPC_BASE.ppc_ns_attrs.len());

    let nsec_reg = &PPC_BASE.ppc_ns_attrs[reg_index];
    nsec_reg.set((nsec_reg.get() & !(1 << bit_index)) | ((allow_non_secure as u32) << bit_index));

    let nsec_priv_reg = &PPC_BASE.ppc_ns_p_attrs[reg_index];
    nsec_priv_reg.set(
        (nsec_priv_reg.get() & !(1 << bit_index)) | ((allow_nsec_nonpriv as u32) << bit_index),
    );
    let sec_priv_reg = &PPC_BASE.ppc_s_p_attrs[reg_index];
    sec_priv_reg
        .set((sec_priv_reg.get() & !(1 << bit_index)) | ((allow_sec_nonpriv as u32) << bit_index));
}

pub fn get_permissions(region: PpcRegion) -> (bool, bool, bool) {
    let region_index = region as usize;
    // 32 regions per 32-bit register
    let reg_index = region_index / 32;
    let bit_index = region_index % 32;

    let allow_non_secure = (PPC_BASE.ppc_ns_attrs[reg_index].get() >> bit_index) & 1 != 0;
    let allow_nsec_nonpriv = (PPC_BASE.ppc_ns_p_attrs[reg_index].get() >> bit_index) & 1 != 0;
    let allow_sec_nonpriv = (PPC_BASE.ppc_s_p_attrs[reg_index].get() >> bit_index) & 1 != 0;

    (allow_non_secure, allow_nsec_nonpriv, allow_sec_nonpriv)
}

pub fn set_protection_context(region: PpcRegion, context: u8) {
    let region_index = region as usize;
    // 4 regions per 32-bit register
    let reg_index = region_index / 4;
    let bit_index = (region_index % 4) * 8;

    let reg = &PPC_BASE.ppc_pc_masks[reg_index];
    reg.set((reg.get() & !(0xFF << bit_index)) | ((context as u32) << bit_index));
}

pub fn lock_protection_contexts() {
    PPC_BASE.ppc_lock_mask.set(0xFF);
}

pub fn set_viloation_response(cfg: FieldValue<u32, PPC_CTL::Register>) {
    PPC_BASE.ppc_ctl.write(cfg);
}
