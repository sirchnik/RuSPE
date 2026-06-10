// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::types;

pub trait PsaApiCallInterface {
    fn psa_framework_version() -> u32;
    fn psa_version(service_id: u32) -> u32;
    fn psa_call(
        handle: types::ServiceHandle,
        ctrl_param: types::CtrlParam,
        in_vec: &[types::FFInVec],
        out_vec: &mut [types::FFOutVec],
    ) -> types::PsaStatus;
}
