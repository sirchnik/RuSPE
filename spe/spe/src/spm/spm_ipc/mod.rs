#![allow(clippy::module_inception, reason = "nested modules under spm_ipc folder")]
pub mod ipc_platform;
pub mod process;
mod spm_ipc;
pub(crate) mod svc_call;

pub use ipc_platform::{CustomMpuRegion, IpcPlatform, IpcProcessPlatform};
pub use process::{IpcProcess, ServiceProcess, ServiceVectors};
pub use spm_ipc::*;
