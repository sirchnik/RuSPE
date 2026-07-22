// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use libtock::platform;
use libtock::platform::{DefaultConfig, ErrorCode, Syscalls};

pub struct SpeDriver<S: Syscalls, C: Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: Config> SpeDriver<S, C> {
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, cmd::EXISTS, 0, 0).to_result()
    }

    pub fn reserve() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, cmd::RESERVE, 0, 0).to_result()
    }

    pub fn release() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, cmd::RELEASE, 0, 0).to_result()
    }

    pub fn is_available() -> Result<bool, ErrorCode> {
        let res = S::command(DRIVER_NUM, cmd::IS_AVAILABLE, 0, 0).to_result::<u32, ErrorCode>()?;
        Ok(res != 0)
    }
}

pub trait Config: platform::allow_ro::Config + platform::allow_rw::Config {}
impl<T: platform::allow_ro::Config + platform::allow_rw::Config> Config for T {}

const DRIVER_NUM: u32 = 0xA0000;

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const RESERVE: u32 = 1;
    pub const RELEASE: u32 = 2;
    pub const IS_AVAILABLE: u32 = 3;
}
