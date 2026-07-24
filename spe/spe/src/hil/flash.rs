// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::StatusCode;

/// Flash errors returned in the callbacks.
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// An error occurred during the flash operation.
    FlashError,

    /// A flash memory protection violation was detected.
    FlashMemoryProtectionError,
}

/// A page of writable persistent flash memory.
pub trait Flash {
    /// Type of a single flash page for the given implementation.
    type Page: AsMut<[u8]> + Default;

    /// Read a page of flash into the buffer.
    fn read_page(
        &self,
        page_number: usize,
        buf: &'static mut Self::Page,
    ) -> Result<(), (StatusCode, &'static mut Self::Page)>;

    /// Write a page of flash from the buffer.
    fn write_page(
        &self,
        page_number: usize,
        buf: &'static mut Self::Page,
    ) -> Result<(), (StatusCode, &'static mut Self::Page)>;

    /// Erase a page of flash by setting every byte to 0xFF.
    fn erase_page(&self, page_number: usize) -> Result<(), StatusCode>;
}
