// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cortex_m::sau;
use tock_psc3::ppc;
use tock_psc3::ppc::PpcRegion;

const NONSECURE_PRIV: &[PpcRegion] = &[
    PpcRegion::ProtPeri0Main,
    PpcRegion::ProtPeri0Gr0Group,
    PpcRegion::ProtPeri0Gr1Group,
    PpcRegion::ProtPeri0Gr2Group,
    PpcRegion::ProtPeri0Gr3Group,
    PpcRegion::ProtPeri0Gr4Group,
    PpcRegion::ProtPeri0Gr5Group,
    PpcRegion::ProtPeri0Gr0Boot,
    PpcRegion::ProtPeri0Gr1Boot,
    PpcRegion::ProtPeri0Gr2Boot,
    PpcRegion::ProtPeri0Gr3Boot,
    PpcRegion::ProtPeri0Gr4Boot,
    PpcRegion::ProtPeri0Gr5Boot,
    PpcRegion::ProtPeri0Tr,
    PpcRegion::ProtPpc0PpcPpcSecure,
    PpcRegion::ProtPpc0PpcPpcNonsecure,
    PpcRegion::ProtPeriPclk0Main,
    PpcRegion::ProtCpuss,
    PpcRegion::ProtRamc0Cm33,
    PpcRegion::ProtRamc0Boot,
    PpcRegion::ProtRamc0RamPwr,
    PpcRegion::ProtRamc0Mpc0PpcMpcMain,
    PpcRegion::ProtRamc0Mpc0PpcMpcPc,
    PpcRegion::ProtRamc0Mpc0PpcMpcRot,
    PpcRegion::ProtPromcCm33,
    PpcRegion::ProtPromcMpc0PpcMpcMain,
    PpcRegion::ProtPromcMpc0PpcMpcPc,
    PpcRegion::ProtPromcMpc0PpcMpcRot,
    PpcRegion::ProtFlashcBoot,
    PpcRegion::ProtFlashcBoot1,
    PpcRegion::ProtFlashcMain,
    PpcRegion::ProtFlashcDft,
    PpcRegion::ProtFlashcEcc,
    PpcRegion::ProtFlashcMpc0PpcMpcMain,
    PpcRegion::ProtFlashcMpc0PpcMpcPc,
    PpcRegion::ProtFlashcMpc0PpcMpcRot,
    PpcRegion::ProtFlashcFmCtlFmDft,
    PpcRegion::ProtFlashcFmCtlFmBoot,
    PpcRegion::ProtFlashcFmCtlFmMain,
    PpcRegion::ProtMxcm33Cm33,
    PpcRegion::ProtMxcm33Cm33S,
    PpcRegion::ProtMxcm33Cm33Ns,
    PpcRegion::ProtMxcm33BootPc0,
    PpcRegion::ProtMxcm33BootPc1,
    PpcRegion::ProtMxcm33BootPc2,
    PpcRegion::ProtMxcm33BootPc3,
    PpcRegion::ProtMxcm33Boot,
    PpcRegion::ProtMxcm33Cm33Int,
    PpcRegion::ProtDw0Dw,
    PpcRegion::ProtDw1Dw,
    PpcRegion::ProtDw0DwCrc,
    PpcRegion::ProtDw1DwCrc,
    PpcRegion::ProtDw0ChStruct0Ch,
    PpcRegion::ProtDw0ChStruct1Ch,
    PpcRegion::ProtDw0ChStruct2Ch,
    PpcRegion::ProtDw0ChStruct3Ch,
    PpcRegion::ProtDw0ChStruct4Ch,
    PpcRegion::ProtDw0ChStruct5Ch,
    PpcRegion::ProtDw0ChStruct6Ch,
    PpcRegion::ProtDw0ChStruct7Ch,
    PpcRegion::ProtDw0ChStruct8Ch,
    PpcRegion::ProtDw0ChStruct9Ch,
    PpcRegion::ProtDw0ChStruct10Ch,
    PpcRegion::ProtDw0ChStruct11Ch,
    PpcRegion::ProtDw0ChStruct12Ch,
    PpcRegion::ProtDw0ChStruct13Ch,
    PpcRegion::ProtDw0ChStruct14Ch,
    PpcRegion::ProtDw0ChStruct15Ch,
    PpcRegion::ProtDw1ChStruct0Ch,
    PpcRegion::ProtDw1ChStruct1Ch,
    PpcRegion::ProtDw1ChStruct2Ch,
    PpcRegion::ProtDw1ChStruct3Ch,
    PpcRegion::ProtDw1ChStruct4Ch,
    PpcRegion::ProtDw1ChStruct5Ch,
    PpcRegion::ProtDw1ChStruct6Ch,
    PpcRegion::ProtDw1ChStruct7Ch,
    PpcRegion::ProtDw1ChStruct8Ch,
    PpcRegion::ProtDw1ChStruct9Ch,
    PpcRegion::ProtDw1ChStruct10Ch,
    PpcRegion::ProtDw1ChStruct11Ch,
    PpcRegion::ProtDw1ChStruct12Ch,
    PpcRegion::ProtDw1ChStruct13Ch,
    PpcRegion::ProtDw1ChStruct14Ch,
    PpcRegion::ProtDw1ChStruct15Ch,
    PpcRegion::ProtCpussAllPc,
    PpcRegion::ProtCpussDdft,
    PpcRegion::ProtCpussCm33S,
    PpcRegion::ProtCpussCm33Ns,
    PpcRegion::ProtCpussMscInt,
    PpcRegion::ProtCpussAp,
    PpcRegion::ProtCpussBoot,
    PpcRegion::ProtMs0Main,
    PpcRegion::ProtMs4Main,
    PpcRegion::ProtMs5Main,
    PpcRegion::ProtMs7Main,
    PpcRegion::ProtMs31Main,
    PpcRegion::ProtMsPc0Priv,
    PpcRegion::ProtMsPc31Priv,
    PpcRegion::ProtMsPc0PrivMir,
    PpcRegion::ProtMsPc31PrivMir,
    PpcRegion::ProtMscAcg,
    PpcRegion::ProtCpussSlCtlGroup,
    PpcRegion::ProtIpcStruct0Ipc,
    PpcRegion::ProtIpcStruct1Ipc,
    PpcRegion::ProtIpcStruct2Ipc,
    PpcRegion::ProtIpcStruct3Ipc,
    PpcRegion::ProtIpcIntrStruct0Intr,
    PpcRegion::ProtIpcIntrStruct1Intr,
    PpcRegion::ProtFaultStruct0Main,
    PpcRegion::ProtSrssGeneral,
    PpcRegion::ProtSrssGeneral2,
    PpcRegion::ProtSrssHibData,
    PpcRegion::ProtSrssMain,
    PpcRegion::ProtSrssSecure,
    PpcRegion::ProtRamTrimSrssSram,
    PpcRegion::ProtSrssDpll,
    PpcRegion::ProtSrssWdt,
    PpcRegion::ProtMain,
    PpcRegion::ProtPwrmodePwrmode,
    PpcRegion::ProtBackupBackup,
    PpcRegion::ProtBackupBBreg0,
    PpcRegion::ProtBackupBBreg1,
    PpcRegion::ProtBackupBBreg2,
    PpcRegion::ProtBackupBBreg3,
    PpcRegion::ProtBackupBackupSecure,
    PpcRegion::ProtCryptoliteMain,
    // PpcRegion::ProtCryptoliteTrng, // used for bootseed in attest service
    PpcRegion::ProtMxcordic10,
    PpcRegion::ProtDebug600Debug600,
    PpcRegion::ProtHsiomPrt0Prt,
    PpcRegion::ProtHsiomPrt1Prt,
    PpcRegion::ProtHsiomPrt2Prt,
    PpcRegion::ProtHsiomPrt3Prt,
    PpcRegion::ProtHsiomPrt4Prt,
    PpcRegion::ProtHsiomPrt5Prt,
    PpcRegion::ProtHsiomPrt6Prt,
    PpcRegion::ProtHsiomPrt7Prt,
    PpcRegion::ProtHsiomPrt8Prt,
    PpcRegion::ProtHsiomPrt9Prt,
    PpcRegion::ProtHsiomSecurePrt0SecurePrt,
    PpcRegion::ProtHsiomSecurePrt1SecurePrt,
    PpcRegion::ProtHsiomSecurePrt2SecurePrt,
    PpcRegion::ProtHsiomSecurePrt3SecurePrt,
    PpcRegion::ProtHsiomSecurePrt4SecurePrt,
    PpcRegion::ProtHsiomSecurePrt5SecurePrt,
    PpcRegion::ProtHsiomSecurePrt6SecurePrt,
    PpcRegion::ProtHsiomSecurePrt7SecurePrt,
    PpcRegion::ProtHsiomSecurePrt8SecurePrt,
    PpcRegion::ProtHsiomSecurePrt9SecurePrt,
    PpcRegion::ProtHsiomAmux,
    PpcRegion::ProtHsiomMon,
    PpcRegion::ProtGpioPrt0Prt,
    PpcRegion::ProtGpioPrt1Prt,
    PpcRegion::ProtGpioPrt2Prt,
    PpcRegion::ProtGpioPrt3Prt,
    PpcRegion::ProtGpioPrt4Prt,
    PpcRegion::ProtGpioPrt5Prt,
    PpcRegion::ProtGpioPrt6Prt,
    PpcRegion::ProtGpioPrt7Prt,
    PpcRegion::ProtGpioPrt8Prt,
    PpcRegion::ProtGpioPrt9Prt,
    PpcRegion::ProtGpioPrt0Cfg,
    PpcRegion::ProtGpioPrt1Cfg,
    PpcRegion::ProtGpioPrt2Cfg,
    PpcRegion::ProtGpioPrt3Cfg,
    PpcRegion::ProtGpioPrt4Cfg,
    PpcRegion::ProtGpioPrt5Cfg,
    PpcRegion::ProtGpioPrt6Cfg,
    PpcRegion::ProtGpioPrt7Cfg,
    PpcRegion::ProtGpioPrt8Cfg,
    PpcRegion::ProtGpioPrt9Cfg,
    PpcRegion::ProtGpioSecGpio,
    PpcRegion::ProtGpioGpio,
    PpcRegion::ProtGpioTest,
    PpcRegion::ProtSmartioPrt0Prt,
    PpcRegion::ProtSmartioPrt1Prt,
    PpcRegion::ProtSmartioPrt2Prt,
    PpcRegion::ProtSmartioPrt3Prt,
    PpcRegion::ProtSmartioPrt5Prt,
    PpcRegion::ProtSmartioPrt6Prt,
    PpcRegion::ProtSmartioPrt9Prt,
    PpcRegion::ProtLpcomp,
    PpcRegion::ProtDft,
    PpcRegion::ProtEfuseCtl1,
    PpcRegion::ProtEfuseCtl2,
    // PpcRegion::ProtEfuseCtl3, // used for lifecycle state in attest service
    PpcRegion::ProtEfuseDataBoot1,
    PpcRegion::ProtCanfd0Ch0Ch,
    PpcRegion::ProtCanfd0Ch1Ch,
    PpcRegion::ProtCanfd0Main,
    PpcRegion::ProtCanfd0Buf,
    // PpcRegion::ProtScb0, // used as secure uart
    PpcRegion::ProtScb1,
    PpcRegion::ProtScb2,
    PpcRegion::ProtScb3,
    PpcRegion::ProtScb4,
    PpcRegion::ProtScb5,
    PpcRegion::ProtTcpwm0Grp0Cnt0Cnt,
    PpcRegion::ProtTcpwm0Grp0Cnt1Cnt,
    PpcRegion::ProtTcpwm0Grp0Cnt2Cnt,
    PpcRegion::ProtTcpwm0Grp0Cnt3Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt0Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt1Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt2Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt3Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt4Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt5Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt6Cnt,
    PpcRegion::ProtTcpwm0Grp1Cnt7Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt0Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt1Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt2Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt3Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt4Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt5Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt6Cnt,
    PpcRegion::ProtTcpwm0Grp2Cnt7Cnt,
    PpcRegion::ProtTcpwm0TrAllGfTrAllGf,
    PpcRegion::ProtTcpwm0TrAllSyncBypassTrAllSynBypass,
    PpcRegion::ProtTcpwm0Boot,
    PpcRegion::ProtTcpwm0MotifGrp1Motif0Motif,
    PpcRegion::ProtMcpass,
];

pub fn configure_security(
    nonsecure_flash_start: u32,
    nonsecure_flash_limit: u32,
    nonsecure_ram_start: u32,
    nonsecure_ram_limit: u32,
    restrict_unprivileged: bool,
) {
    let nsc_start = nonsecure_flash_start
        .wrapping_add(0x1000_0000)
        .wrapping_sub(0x100);

    // Sometimes while debugging no BUS_ERROR is generated and the debugger just
    // hangs. Change to RZWI then.
    ppc::set_viloation_response(ppc::PPC_CTL::RESP_CFG::BUS_ERROR);

    for region in NONSECURE_PRIV.iter().copied() {
        ppc::set_permissions(region, true, false, false);
        ppc::set_protection_context(region, 0xFF);
    }

    // TODO should be inverted
    ppc::set_permissions(PpcRegion::ProtCryptoliteTrng, true, true, false);
    ppc::set_permissions(PpcRegion::ProtEfuseCtl3, true, true, false);

    ppc::lock_protection_contexts();

    let mut sau = sau::new();

    sau.set_region(
        0,
        sau::SauRegion {
            base_address: nonsecure_flash_start,
            limit_address: nonsecure_flash_limit,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();

    sau.set_region(
        1,
        sau::SauRegion {
            base_address: nsc_start,
            limit_address: nsc_start + 0xFF,
            attribute: sau::SauRegionAttribute::NonSecureCallable,
        },
    )
    .unwrap();

    sau.set_region(
        2,
        sau::SauRegion {
            base_address: nonsecure_ram_start,
            limit_address: nonsecure_ram_limit,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();

    sau.set_region(
        3,
        sau::SauRegion {
            base_address: 0x2400_F000,
            limit_address: 0x2400_FFFF,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();

    sau.set_region(
        4,
        sau::SauRegion {
            base_address: 0x4200_0000,
            limit_address: 0x4FFF_FFFF,
            attribute: sau::SauRegionAttribute::NonSecure,
        },
    )
    .unwrap();

    sau.set_region(
        5,
        sau::SauRegion {
            base_address: 0x5202_0000,
            limit_address: 0x5202_637F,
            attribute: sau::SauRegionAttribute::Secure,
        },
    )
    .unwrap();

    sau.set_region(
        6,
        sau::SauRegion {
            base_address: 0x5282_0000,
            limit_address: 0x5282_0FDF,
            attribute: sau::SauRegionAttribute::Secure,
        },
    )
    .unwrap();

    sau.enable();

    if restrict_unprivileged {
        use cortex_m::mpu::{MPU, Permissions};
        let mpu = unsafe { MPU::<8>::new() };
        let mut config = mpu.new_config().expect("MPU config slots exhausted");

        mpu.allocate_region(
            0x3201FF00 as *const u8,
            0x100,
            Permissions::ReadOnly,
            &mut config,
        )
        .unwrap();

        unsafe { mpu.configure_mpu(&config) };
        mpu.enable_mpu();
    }
}
