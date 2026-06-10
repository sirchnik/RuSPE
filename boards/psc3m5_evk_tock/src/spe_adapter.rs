use kernel::{
    syscall::{CommandReturn, SyscallDriver},
    ErrorCode,
};

use psa_interface::{
    psa_api,
    status::StatusCode,
    types::PsaStatus,
};
use psa_veneer_client::PsaVeneerClient;

pub const DRIVER_NUM: usize = 0xa0000;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Cmd {
    PsaCall = 0,
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

fn psa_status_to_command_return(status: Result<(), PsaStatus>) -> CommandReturn {
    match status {
        Ok(()) => CommandReturn::success(),
        Err(status) => match StatusCode::try_from(status) {
            Ok(status_code) => CommandReturn::failure(psa_status_to_error_code(status_code)),
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        },
    }
}

pub struct SpeAdapter;

impl SyscallDriver for SpeAdapter {
    fn command(
        &self,
        cmd_num: usize,
        _: usize,
        _: usize,
        _process_id: kernel::ProcessId,
    ) -> kernel::syscall::CommandReturn {
        if cmd_num == Cmd::PsaCall as usize {
            let challenge = [0u8; 32];
            let mut token_buf = [0u8; 512];

            let status = psa_api::initial_attest_get_token::<PsaVeneerClient>(
                &challenge,
                &mut token_buf,
            );

            psa_status_to_command_return(status)
        } else {
            CommandReturn::failure(ErrorCode::INVAL)
        }
    }

    fn allocate_grant(&self, _process_id: kernel::ProcessId) -> Result<(), kernel::process::Error> {
        // No-op implementation
        Ok(())
    }
}
