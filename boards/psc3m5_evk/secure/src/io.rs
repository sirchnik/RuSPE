// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::cell::Cell;
use core::panic::PanicInfo;

use tock_psc3::scb;

pub struct Writer {
    serial: Cell<Option<&'static scb::Scb<'static>>>,
}

impl Writer {
    pub fn set_serial(&self, scb: &'static scb::Scb<'static>) {
        self.serial.set(Some(scb));
    }
}

#[cfg(debug_assertions)]
impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.serial
            .get()
            .map(|serial| serial.transmit_uart_sync(s.as_bytes()));
        Ok(())
    }
}

pub static mut WRITER: Writer = Writer {
    serial: Cell::new(None),
};

/// This function is called on panic, and it will attempt to print the panic
/// message to the serial port. It also blinks the LED to indicate a panic has
/// occurred.
#[cfg(debug_assertions)]
#[panic_handler]
pub fn panic_fmt(pi: &PanicInfo) -> ! {
    use core::fmt::Write;
    use core::ptr::addr_of_mut;
    let writer = unsafe { &mut *addr_of_mut!(WRITER) };

    writer.write_fmt(format_args!("\r\n{}\r\n", pi)).unwrap();

    loop {}
}

#[cfg(not(debug_assertions))]
#[panic_handler]
pub fn panic_fmt(_pi: &PanicInfo) -> ! {
    loop {}
}

#[cfg(debug_assertions)]
pub fn debugln(args: core::fmt::Arguments) {
    use core::fmt::Write;
    use core::ptr::addr_of_mut;
    let writer = unsafe { &mut *addr_of_mut!(WRITER) };

    writer.write_fmt(args).unwrap();
}
