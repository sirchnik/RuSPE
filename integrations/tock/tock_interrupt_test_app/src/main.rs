// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_main]
#![no_std]
#![allow(dead_code)]

use core::fmt::Write;
use libtock::buttons::{ButtonListener, Buttons};
use libtock::console::Console;
use libtock::leds::Leds;
use libtock::platform::Syscalls;
use libtock::platform::share;
use libtock::runtime::{TockSyscalls, set_main, stack_size};

set_main! {main}
stack_size! {0x400}

fn main() {
    let listener = ButtonListener(|button, _state| {
        let _ = Leds::toggle(button);
        writeln!(Console::writer(), "button-{button:?}").unwrap();
    });
    if let Ok(buttons_count) = Buttons::count() {
        writeln!(Console::writer(), "button count: {buttons_count}").unwrap();

        share::scope(|subscribe| {
            // Subscribe to the button callback.
            Buttons::register_listener(&listener, subscribe).unwrap();

            // Enable interrupts for each button press.
            for i in 0..buttons_count {
                Buttons::enable_interrupts(i).unwrap();
            }

            // Wait for buttons to be pressed.
            loop {
                TockSyscalls::yield_wait();
            }
        });
    }
}
