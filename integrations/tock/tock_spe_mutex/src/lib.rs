// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]

use core::cell::Cell;

use enum_primitive::cast::FromPrimitive;
use enum_primitive::enum_from_primitive;
use kernel::process::Error;
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

pub const DRIVER_NUM: usize = 0xa0000;

enum_from_primitive! {
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Cmd {
    Exists = 0,
    Reserve = 1,
    Release = 2,
    IsAvailable = 3,
}
}

pub struct SpeMutex {
    owner: Cell<Option<ProcessId>>,
}

impl SpeMutex {
    pub const fn new() -> Self {
        Self {
            owner: Cell::new(None),
        }
    }
}

impl Default for SpeMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl SpeMutex {
    fn reserve(&self, process_id: ProcessId) -> CommandReturn {
        match self.owner.get() {
            None => {
                self.owner.set(Some(process_id));
                CommandReturn::success()
            }
            Some(owner_id) if owner_id == process_id => CommandReturn::failure(ErrorCode::ALREADY),
            Some(_) => CommandReturn::failure(ErrorCode::BUSY),
        }
    }

    fn release(&self, process_id: ProcessId) -> CommandReturn {
        match self.owner.get() {
            Some(owner_id) if owner_id == process_id => {
                self.owner.set(None);
                CommandReturn::success()
            }
            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn is_available(&self) -> CommandReturn {
        if self.owner.get().is_none() {
            CommandReturn::success_u32(1)
        } else {
            CommandReturn::success_u32(0)
        }
    }
}

impl SyscallDriver for SpeMutex {
    fn command(
        &self,
        cmd_num: usize,
        _arg1: usize,
        _arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        if cmd_num == 0 {
            return CommandReturn::success();
        }

        let cmd = Cmd::from_usize(cmd_num);
        let Some(cmd) = cmd else {
            return CommandReturn::failure(ErrorCode::INVAL);
        };

        match cmd {
            Cmd::Exists => CommandReturn::success(),
            Cmd::Reserve => self.reserve(process_id),
            Cmd::Release => self.release(process_id),
            Cmd::IsAvailable => self.is_available(),
        }
    }

    fn allocate_grant(&self, _process_id: ProcessId) -> Result<(), Error> {
        Err(Error::NoSuchApp)
    }
}
