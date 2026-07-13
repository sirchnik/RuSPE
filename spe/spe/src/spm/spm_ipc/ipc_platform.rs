// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cortex_m::mpu::Permissions;
use psa_interface::types::ServiceHandle;

use super::process::ServiceVectors;
use crate::spm_api::CallerAttributes;

#[derive(Clone, Copy)]
pub struct CustomMpuRegion {
    pub base: *const u8,
    pub size: usize,
    pub permissions: Permissions,
}

pub trait IpcPlatform: Sync {
    fn has_permission_on_memory(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool;

    fn custom_mpu_regions(&self, _handle: ServiceHandle) -> &[CustomMpuRegion];
}

pub trait IpcProcessPlatform: IpcPlatform {
    fn prepare_process(&self, _vectors: &ServiceVectors) {}
}
