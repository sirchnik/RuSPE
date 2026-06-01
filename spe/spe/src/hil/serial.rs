// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Serial trait

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialError {
    Busy,
    Size,
    NoSupport,
    Off,
    Fail,
}

pub trait SerialSync {
    fn initialize(&self) -> Result<(), SerialError>;

    fn uninitialize(&self) -> Result<(), SerialError>;

    fn send(&self, data: &[u8]) -> Result<(), (SerialError, &'static mut [u8])>;

    fn receive(
        &self,
        data: &'static mut [u8],
        num: usize,
    ) -> Result<(), (SerialError, &'static mut [u8])>;

    fn transfer(
        &self,
        data_out: &'static mut [u8],
        data_in: &'static mut [u8],
        num: usize,
    ) -> Result<(), (SerialError, &'static mut [u8], &'static mut [u8])>;
}
