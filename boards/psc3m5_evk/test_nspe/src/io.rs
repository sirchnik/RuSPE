// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Board-level I/O and panic infrastructure for the PSC3M5-EVK.

use core::cell::Cell;
use core::fmt::Write;
use core::panic::PanicInfo;

use psc3::scb::Scb;

/// Writer is used to panic message to the serial port.
pub struct Writer {
    scb: Cell<Option<&'static Scb<'static>>>,
}

impl Writer {
    pub fn set_scb(&self, scb: &'static Scb) {
        self.scb.set(Some(scb));
    }
}

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if let Some(scb) = self.scb.get() {
            scb.transmit_uart_sync(s.as_bytes());
        }
        Ok(())
    }
}

pub static mut WRITER: Writer = Writer {
    scb: Cell::new(None),
};

/// This function is called on panic, and it will attempt to print the panic message to the serial port.
/// It also blinks the LED to indicate a panic has occurred.
#[panic_handler]
pub fn panic_fmt(pi: &PanicInfo) -> ! {
    use core::ptr::addr_of_mut;
    let writer = unsafe { &mut *addr_of_mut!(WRITER) };

    writer.write_fmt(format_args!("\r\n{}\r\n", pi)).unwrap();

    loop {}
}
