// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! Board-level I/O and panic infrastructure for Musca-B1.

use core::cell::Cell;
use core::fmt::Write;
use core::panic::PanicInfo;

use ruspe_musca_b1::uart::UartMin;

/// Writer is used to panic message to the serial port.
pub struct Writer {
    uart: Cell<Option<&'static UartMin>>,
}

/// Global static for debug writer
pub static mut WRITER: Writer = Writer {
    uart: Cell::new(None),
};

impl Writer {
    /// Set the Uart peripheral to use
    pub fn set_uart(&self, uart: &'static UartMin) {
        self.uart.set(Some(uart));
    }
}

impl Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if let Some(uart) = self.uart.get() {
            for b in s.as_bytes() {
                uart.send_byte(*b);
            }
        }
        Ok(())
    }
}

/// This function is called on panic, and it will attempt to print the panic message to the serial port.
#[panic_handler]
pub fn panic_fmt(pi: &PanicInfo) -> ! {
    use core::ptr::addr_of_mut;
    let writer = unsafe { &mut *addr_of_mut!(WRITER) };

    let _ = writer.write_fmt(format_args!("\r\n{}\r\n", pi));

    loop {}
}

pub fn debugln(args: core::fmt::Arguments) {
    use core::ptr::addr_of_mut;
    let writer = unsafe { &mut *addr_of_mut!(WRITER) };

    writer.write_fmt(args).unwrap();
}
