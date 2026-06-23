// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::cell::Cell;
use core::{fmt::Write, panic::PanicInfo};
use tock_musca_b1::uart;

pub struct Writer {
    serial: Cell<Option<&'static uart::Uart<'static>>>,
}

impl Writer {
    pub fn set_serial(&self, serial: &'static uart::Uart<'static>) {
        self.serial.set(Some(serial));
    }
}

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.serial
            .get()
            .map(|serial| {
                for b in s.bytes() {
                    serial.send_byte(b);
                }
            });
        Ok(())
    }
}

pub static mut WRITER: Writer = Writer {
    serial: Cell::new(None),
};

#[panic_handler]
pub fn panic_fmt(pi: &PanicInfo) -> ! {
    use core::ptr::addr_of_mut;
    let writer = unsafe { &mut *addr_of_mut!(WRITER) };

    writer.write_fmt(format_args!("\r\n{}\r\n", pi)).unwrap();

    loop {}
}

pub fn debugln(args: core::fmt::Arguments) {
    use core::ptr::addr_of_mut;
    let writer = unsafe { &mut *addr_of_mut!(WRITER) };

    writer.write_fmt(args).unwrap();
}
