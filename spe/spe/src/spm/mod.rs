mod spm_fn;
mod spm_ipc;

pub use spm_fn::{Connection, PSA_MAX_IOVEC, SpmCall, SpmError, SpmFn, SpmPlatform};
pub use spm_ipc::{EmbeddedProcess, FlashProcess, FlashProcessVectors, IpcProcess, SpmIpc};

#[cfg(all(target_arch = "arm", target_os = "none"))]
pub(crate) fn call_unprivileged(f: impl FnOnce()) {
    use core::arch::asm;

    unsafe {
        asm!(
            "mrs r0, control",
            "orr r0, r0, #1",
            "msr control, r0",
            "isb",
            options(nomem, nostack, preserves_flags),
        );
    }

    f();

    unsafe {
        asm!("svc #0", options(nomem, nostack));
        asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub(crate) fn call_unprivileged(f: impl FnOnce()) {
    f();
}
