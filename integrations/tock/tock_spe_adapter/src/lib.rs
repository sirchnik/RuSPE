// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]

use core::cmp;

use enum_primitive::cast::FromPrimitive;
use enum_primitive::enum_from_primitive;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::{
    ErrorCode, ProcessId,
    grant::GrantKernelData,
    syscall::{CommandReturn, SyscallDriver},
};

use psa_interface::{psa_api, status::StatusCode};
use psa_veneer_client::PsaVeneerClient;

pub const DRIVER_NUM: usize = 0xa0000;

const MAX_CHALLENGE_LEN: usize = 64;
const MAX_TOKEN_LEN: usize = 512;

mod ro_allow {
    pub const CHALLENGE: usize = 0;
    pub const COUNT: u8 = 1;
}

mod rw_allow {
    pub const TOKEN: usize = 0;
    pub const COUNT: u8 = 1;
}

#[derive(Default)]
pub struct App;

enum_from_primitive! {
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Cmd {
    Exists = 0,
    InitialAttestGetToken = 1,
}
}

fn psa_status_to_error_code(status: StatusCode) -> ErrorCode {
    match status {
        StatusCode::_Success => ErrorCode::FAIL,
        StatusCode::ProgrammerError => ErrorCode::INVAL,
        StatusCode::ConnectionRefused => ErrorCode::RESERVE,
        StatusCode::ConnectionBusy => ErrorCode::BUSY,
        StatusCode::GenericError => ErrorCode::FAIL,
        StatusCode::NotPermitted => ErrorCode::RESERVE,
        StatusCode::NotSupported => ErrorCode::NOSUPPORT,
        StatusCode::InvalidArgument => ErrorCode::INVAL,
        StatusCode::InvalidHandle => ErrorCode::NODEVICE,
        StatusCode::BadState => ErrorCode::ALREADY,
        StatusCode::BufferTooSmall => ErrorCode::SIZE,
        StatusCode::AlreadyExists => ErrorCode::ALREADY,
        StatusCode::DoesNotExist => ErrorCode::NODEVICE,
        StatusCode::InsufficientMemory => ErrorCode::NOMEM,
        StatusCode::InsufficientStorage => ErrorCode::NOMEM,
        StatusCode::InsufficientData => ErrorCode::SIZE,
        StatusCode::ServiceFailure => ErrorCode::FAIL,
        StatusCode::CommunicationFailure => ErrorCode::NOACK,
        StatusCode::StorageFailure => ErrorCode::FAIL,
        StatusCode::HardwareFailure => ErrorCode::OFF,
        StatusCode::InvalidSignature => ErrorCode::FAIL,
        StatusCode::CorruptionDetected => ErrorCode::FAIL,
        StatusCode::DataCorrupt => ErrorCode::FAIL,
        StatusCode::DataInvalid => ErrorCode::FAIL,
        StatusCode::OperationIncomplete => ErrorCode::BUSY,
    }
}

fn psa_status_to_command_return(status: Result<(), StatusCode>) -> CommandReturn {
    match status {
        Ok(()) => CommandReturn::success(),
        Err(status) => CommandReturn::failure(psa_status_to_error_code(status)),
    }
}

pub struct SpeAdapter {
    grants: Grant<
        App,
        UpcallCount<0>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
}

impl SpeAdapter {
    pub fn new(
        grants: Grant<
            App,
            UpcallCount<0>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        Self { grants }
    }

    fn read_challenge(
        kernel_data: &GrantKernelData,
        arg1: usize,
        challenge: &mut [u8; MAX_CHALLENGE_LEN],
    ) -> Option<usize> {
        let challenge_buf = kernel_data
            .get_readonly_processbuffer(ro_allow::CHALLENGE)
            .ok()?;

        let len = challenge_buf
            .enter(|src| {
                let requested = if arg1 == 0 {
                    src.len()
                } else {
                    cmp::min(src.len(), arg1)
                };

                if requested == 0 || requested > challenge.len() {
                    return 0;
                }

                for (i, value) in src[..requested].iter().enumerate() {
                    challenge[i] = value.get();
                }
                requested
            })
            .ok()?;

        if len == 0 { None } else { Some(len) }
    }

    fn token_capacity(kernel_data: &GrantKernelData) -> Option<usize> {
        let len = kernel_data
            .get_readwrite_processbuffer(rw_allow::TOKEN)
            .map_or(0, |token_buf| cmp::min(token_buf.len(), MAX_TOKEN_LEN));

        if len == 0 { None } else { Some(len) }
    }

    fn write_token_to_process(
        kernel_data: &GrantKernelData,
        token: &[u8],
        token_len: usize,
    ) -> usize {
        kernel_data
            .get_readwrite_processbuffer(rw_allow::TOKEN)
            .and_then(|token_buf| {
                token_buf.mut_enter(|dst| {
                    let copy_len = cmp::min(dst.len(), token_len);
                    for (i, value) in token[..copy_len].iter().enumerate() {
                        dst[i].set(*value);
                    }
                    copy_len
                })
            })
            .unwrap_or(0)
    }

    fn do_initial_attest_get_token(&self, process_id: ProcessId, arg1: usize) -> CommandReturn {
        self.grants
            .enter(process_id, |_, kernel_data| {
                let mut challenge = [0u8; MAX_CHALLENGE_LEN];
                let challenge_len = match Self::read_challenge(kernel_data, arg1, &mut challenge) {
                    Some(len) => len,
                    None => return CommandReturn::failure(ErrorCode::INVAL),
                };

                let token_len = match Self::token_capacity(kernel_data) {
                    Some(len) => len,
                    None => return CommandReturn::failure(ErrorCode::INVAL),
                };

                let mut token = [0u8; MAX_TOKEN_LEN];
                let status = psa_api::psa_initial_attest_get_token::<PsaVeneerClient>(
                    &challenge[..challenge_len],
                    &mut token[..token_len],
                );

                match status {
                    Ok(()) => {
                        let copied = Self::write_token_to_process(kernel_data, &token, token_len);
                        if copied == 0 {
                            CommandReturn::failure(ErrorCode::FAIL)
                        } else {
                            CommandReturn::success_u32(copied as u32)
                        }
                    }
                    Err(err) => psa_status_to_command_return(Err(err)),
                }
            })
            .unwrap_or(CommandReturn::failure(ErrorCode::NOMEM))
    }
}

impl SyscallDriver for SpeAdapter {
    fn command(
        &self,
        cmd_num: usize,
        arg1: usize,
        _: usize,
        process_id: ProcessId,
    ) -> kernel::syscall::CommandReturn {
        if cmd_num == 0 {
            return CommandReturn::success();
        }

        let cmd = Cmd::from_usize(cmd_num);
        let cmd = match cmd {
            Some(cmd) => cmd,
            None => return CommandReturn::failure(ErrorCode::INVAL),
        };

        match cmd {
            Cmd::Exists => CommandReturn::success(),
            Cmd::InitialAttestGetToken => self.do_initial_attest_get_token(process_id, arg1),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.grants.enter(process_id, |_, _| {})
    }
}
