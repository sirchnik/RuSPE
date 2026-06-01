// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Board‑level I/O and panic infrastructure for the PSC3M5-EVK.

use core::fmt::Write;
use core::panic::PanicInfo;
use kernel::utilities::cells::OptionalCell;

use psc3::scb::Scb;

use kernel::debug::IoWrite;

/// Writer is used by kernel::debug to panic message to the serial port.
pub struct Writer {
    scb: OptionalCell<&'static Scb<'static>>,
}

impl Writer {
    pub fn set_scb(&self, scb: &'static Scb) {
        self.scb.set(scb);
    }
}

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.scb.map(|scb| scb.transmit_uart_sync(s.as_bytes()));
        Ok(())
    }
}

impl IoWrite for Writer {
    fn write(&mut self, buf: &[u8]) -> usize {
        self.scb.map(|scb| scb.transmit_uart_sync(buf));
        buf.len()
    }
}

pub static mut WRITER: Writer = Writer {
    scb: OptionalCell::empty(),
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
