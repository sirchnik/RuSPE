// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::cmp;

use spe::libs::mutex::Mutex;
use spe_services::attest::attest_service::{self, CERTIFICATION_REF_MAX_SIZE};

use crate::cryptolite;
use crate::efuse::{SyslibLcsMode, get_device_lifecycle};

#[repr(u32)]
enum PsaLifecycle {
    Unknown = 0x0000,
    AssemblyAndTest = 0x1000,
    PsaRotProvisioning = 0x2000,
    Secured = 0x3000,
    // NonPsaRotDebug = 0x4000,
    // RecoverablePsaRotDebug = 0x5000,
    Decommissioned = 0x6000,
}

pub struct Psc3AttestPlatform {
    boot_record_addr: Option<usize>,
}

impl Psc3AttestPlatform {
    pub const fn new(boot_record_addr: Option<usize>) -> Self {
        Self { boot_record_addr }
    }
}

impl attest_service::AttestPlatform for Psc3AttestPlatform {
    fn security_lifecycle(&self) -> Result<u32, spe::StatusCode> {
        let lcs = get_device_lifecycle();
        let lifecycle = match lcs {
            SyslibLcsMode::Virgin
            | SyslibLcsMode::Sort
            | SyslibLcsMode::Provisioned
            | SyslibLcsMode::Normal
            | SyslibLcsMode::NormalNoSecure => PsaLifecycle::AssemblyAndTest,
            SyslibLcsMode::NormalProvisioned => PsaLifecycle::PsaRotProvisioning,
            SyslibLcsMode::Secure => PsaLifecycle::Secured,
            SyslibLcsMode::Rma => PsaLifecycle::Decommissioned,
            SyslibLcsMode::Corrupted => PsaLifecycle::Unknown,
        };

        Ok(lifecycle as u32)
    }

    fn verification_service(&self, buf: &mut [u8]) -> Result<usize, spe::StatusCode> {
        let s = b"https://psa-verifier.org";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        Ok(len)
    }

    fn profile_definition(&self, buf: &mut [u8]) -> Result<usize, spe::StatusCode> {
        let s = b"tag:psacertified.org,2023:psa#tfm";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        Ok(len)
    }

    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), spe::StatusCode> {
        struct BootSeedState {
            seed: [u8; 32],
            init: bool,
        }
        static STATE: Mutex<BootSeedState> = Mutex::new(BootSeedState {
            seed: [0; 32],
            init: false,
        });

        STATE
            .try_lock(|state| {
                if !state.init {
                    let cryptolite = cryptolite::Cryptolite::new();
                    if cryptolite
                        .trng_init(&cryptolite::TrngConfig::default())
                        .and_then(|()| cryptolite.trng_enable())
                        .is_err()
                    {
                        return Err(spe::StatusCode::GenericError);
                    }
                    if cryptolite.trng_try_fill_bytes(&mut state.seed).is_err() {
                        return Err(spe::StatusCode::GenericError);
                    }
                    state.init = true;
                }
                seed.copy_from_slice(&state.seed);
                Ok(())
            })
            .map_or(Err(spe::StatusCode::GenericError), |res| res)
    }

    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), spe::StatusCode> {
        let s = b"acme-implementation-id-000000001";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        if len < buf.len() {
            buf[len..].fill(0);
        }
        Ok(())
    }

    fn instance_id(&self, buf: &mut [u8; 33]) -> Result<(), spe::StatusCode> {
        buf[0] = 0x01;
        buf[1..].fill(0x02);
        Ok(())
    }

    fn cert_ref(
        &self,
        buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE],
    ) -> Result<usize, spe::StatusCode> {
        let s = b"0123456789012-12345";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        if len < buf.len() {
            buf[len..].fill(0);
        }
        Ok(len)
    }

    fn boot_record(&self) -> Option<&'static [u8]> {
        let addr = self.boot_record_addr?;
        // SAFETY: boot_record_addr points to a valid boot record structure in memory,
        // and we safely check the magic number before slicing the memory region.
        unsafe {
            let ptr = addr as *const u8;
            let magic = u16::from_le_bytes([*ptr, *ptr.add(1)]);
            if magic == 0x2016 {
                Some(core::slice::from_raw_parts(ptr, 0x100))
            } else {
                None
            }
        }
    }
}

pub type InitialAttestation<C> = attest_service::AttestService<Psc3AttestPlatform, C>;
