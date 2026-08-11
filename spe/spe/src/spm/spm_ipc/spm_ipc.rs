// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cortex_m::mpu::MpuConfig;
use psa_interface::types::ServiceHandle;

use crate::libs::mutex::{Mutex, TryLockError};
use crate::spm::spm::{Connection, ConnectionArray, SpmCall, SpmError};
use crate::spm::spm_ipc::ipc_platform::IpcProcessPlatform;
use crate::spm::spm_ipc::process::{IpcProcess, ServiceProcess};
use crate::spm_api::{CallerAttributes, MaybeUsize};

// ---------------------------------------------------------------------------
// SpmIpc - IPC-style SPM dispatcher
// ---------------------------------------------------------------------------

struct SpmIpcState<const N: usize> {
    connections: ConnectionArray,
    init_done: [bool; N],
}

impl<const N: usize> SpmIpcState<N> {
    pub const fn new() -> Self {
        Self {
            connections: ConnectionArray::new(),
            init_done: [false; N],
        }
    }

    fn mark_init_done(&mut self, index: usize) -> Result<bool, SpmError> {
        if index >= N {
            return Err(SpmError::CorruptedConnectionStack);
        }

        let Some(slot) = self.init_done.get_mut(index) else {
            return Err(SpmError::CorruptedConnectionStack);
        };

        if *slot {
            Ok(false)
        } else {
            *slot = true;
            Ok(true)
        }
    }
}

pub struct SpmIpc<
    P: IpcProcessPlatform + 'static,
    const N: usize,
    Proc: IpcProcess = ServiceProcess,
> {
    state: Mutex<SpmIpcState<N>>,
    platform: &'static P,
    processes: [Proc; N],
}

impl<P: IpcProcessPlatform + 'static, const N: usize, Proc: IpcProcess> SpmIpc<P, N, Proc> {
    pub const fn new(platform: &'static P, processes: [Proc; N]) -> Self {
        Self {
            state: Mutex::new(SpmIpcState::new()),
            platform,
            processes,
        }
    }

    fn find_process_index(&self, handle: ServiceHandle) -> Option<usize> {
        self.processes
            .iter()
            .position(|process| (process.handle() as isize) == (handle as isize))
    }

    fn with_active_connection<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> R,
    ) -> Result<R, SpmError> {
        let (index, mut connection) = match self
            .state
            .try_lock(|state| state.connections.take_active_connection())
        {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(SpmError::MutexBusy),
        };

        let result = f(&mut connection);

        match self.state.try_lock(|state| {
            state
                .connections
                .restore_active_connection(index, connection)
        }) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(SpmError::MutexBusy),
        }
        Ok(result)
    }

    fn update_vec_mapping(&self, is_outvec: bool, vec_idx: u32, mapped: bool) {
        let mut process_index_opt = None;
        let _ = self.with_active_connection(|conn| {
            if let Some(p_idx) = self.find_process_index(conn.msg.handle) {
                process_index_opt = Some(p_idx);
                let idx = vec_idx as usize;
                if is_outvec {
                    if let Some(slot) = conn.outvec_mapped.get_mut(idx) {
                        *slot = mapped;
                    }
                    if let Some(slot) = conn.outvec_unmapped.get_mut(idx) {
                        *slot = !mapped;
                    }
                } else {
                    if let Some(slot) = conn.invec_mapped.get_mut(idx) {
                        *slot = mapped;
                    }
                    if let Some(slot) = conn.invec_unmapped.get_mut(idx) {
                        *slot = !mapped;
                    }
                }
            }
        });

        if let Some(process_index) = process_index_opt {
            self.apply_mpu_config(process_index);
        }
    }

    fn apply_mpu_config(&self, process_index: usize) {
        use cortex_m::mpu::{Mpu, Permissions};

        let Some(proc) = self.processes.get(process_index) else {
            return;
        };
        let vectors = proc.get_vectors();
        let Some(vectors) = vectors else {
            return;
        };

        let mpu = Mpu::<8>::new();

        let mut config = MpuConfig::default();

        let rom = vectors.rom_region();
        let ram = vectors.ram_region();
        let _ = mpu.allocate_region(rom.base, rom.size, Permissions::ReadExecute, &mut config);
        let _ = mpu.allocate_region(ram.base, ram.size, Permissions::ReadWriteXN, &mut config);

        let handle = proc.handle();
        for region in self.platform.custom_mpu_regions(handle) {
            let _ = mpu.allocate_region(region.base, region.size, region.permissions, &mut config);
        }

        let mut allocate_vec = |base_addr: u32, size: u32, permissions| {
            if size > 0 {
                let aligned_base = base_addr & !0x1F;
                let aligned_end = (base_addr + size + 0x1F) & !0x1F;
                let aligned_size = aligned_end - aligned_base;
                let _ = mpu.allocate_region(
                    aligned_base as *const u8,
                    aligned_size,
                    permissions,
                    &mut config,
                );
            }
        };

        let _ = self.state.try_lock(|state| {
            if let Ok(conn) = state.connections.peek_active_connection()
                && self.find_process_index(conn.msg.handle) == Some(process_index)
            {
                for i in 0..conn.invec_mapped.len() {
                    if conn.invec_mapped.get(i) == Some(&true)
                        && conn.invec_unmapped.get(i) == Some(&false)
                        && let Some(Some(size)) = conn.msg.in_size.get(i).map(MaybeUsize::as_option)
                        && let Some(&base) = conn.invec_base.get(i)
                    {
                        allocate_vec(base as u32, size as u32, Permissions::ReadXN);
                    }
                }
                for i in 0..conn.outvec_mapped.len() {
                    if conn.outvec_mapped.get(i) == Some(&true)
                        && conn.outvec_unmapped.get(i) == Some(&false)
                        && let Some(Some(size)) =
                            conn.msg.out_size.get(i).map(MaybeUsize::as_option)
                        && let Some(&base) = conn.outvec_base.get(i)
                    {
                        allocate_vec(base as u32, size as u32, Permissions::ReadWriteXN);
                    }
                }
            }
        });

        // SAFETY: `config` contains validated MPU regions. Configuring and enabling
        // the MPU restricts access to memory according to the specified permissions,
        // which enforces process isolation.
        unsafe {
            mpu.configure_mpu(&config);
            mpu.enable_mpu();
        }
    }

    // inline(never) for fixing bug in O3
    #[inline(never)]
    fn get_last_process_index(&self) -> Option<usize> {
        self.state
            .try_lock(|state| {
                state.connections.pop_connection();
                state
                    .connections
                    .peek_active_connection()
                    .ok()
                    .and_then(|conn| self.find_process_index(conn.msg.handle))
            })
            .ok()
            .flatten()
    }
}

impl<P: IpcProcessPlatform + 'static, const N: usize, Proc: IpcProcess> SpmCall
    for SpmIpc<P, N, Proc>
{
    fn call(&self, connection: &Connection) -> Result<(), crate::StatusCode> {
        let Some(process_index) = self.find_process_index(connection.msg.handle) else {
            return Err(crate::StatusCode::NotSupported);
        };

        let msg = connection.msg;

        let should_init = match self.state.try_lock(|state| {
            state.connections.add_connection(connection)?;
            state.mark_init_done(process_index)
        }) {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => return Err(crate::StatusCode::InsufficientMemory),
            Err(TryLockError) => return Err(crate::StatusCode::ConnectionBusy),
        };

        self.apply_mpu_config(process_index);

        self.processes
            .get(process_index)
            .map_or(Err(crate::StatusCode::NotSupported), |proc| {
                if should_init {
                    proc.init_process(self.platform, self);
                }

                let result = proc.call_process(self.platform, self, msg);

                // Restore MPU of previous process, if any
                let prev_process_index = self.get_last_process_index();

                if let Some(prev) = prev_process_index {
                    self.apply_mpu_config(prev);
                }

                result
            })
    }

    fn with_active_connection<F: FnMut(&mut Connection)>(&self, mut f: F) -> Result<(), SpmError> {
        self.with_active_connection(|conn| f(conn))
    }

    fn has_real_permission(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool {
        self.platform
            .has_permission_on_memory(base, len, is_write, caller)
    }

    fn map_vec(&self, is_outvec: bool, vec_idx: u32, _base: *const u8, _size: usize) {
        self.update_vec_mapping(is_outvec, vec_idx, true);
    }

    fn unmap_vec(&self, is_outvec: bool, vec_idx: u32) {
        self.update_vec_mapping(is_outvec, vec_idx, false);
    }

    fn version(&self, handle: ServiceHandle) -> Option<u32> {
        self.find_process_index(handle).and_then(|i| {
            self.processes
                .get(i)
                .map(super::process::IpcProcess::version)
        })
    }
}

#[cfg(test)]
mod tests {
    use psa_interface::types::ServiceHandle;

    use super::*;
    use crate::spm::spm_ipc::{
        CustomMpuRegion, IpcPlatform, IpcProcess, IpcProcessPlatform, ServiceVectors,
    };
    use crate::spm_api::{CallerAttributes, PsaMsg};

    #[test]
    fn test_spm_ipc_state_init() {
        let mut state = SpmIpcState::<2>::new();
        assert_eq!(state.mark_init_done(0), Ok(true));
        assert_eq!(state.mark_init_done(0), Ok(false)); // already done

        assert_eq!(state.mark_init_done(1), Ok(true));

        // Out of bounds
        assert_eq!(
            state.mark_init_done(2),
            Err(SpmError::CorruptedConnectionStack)
        );
    }

    struct MockPlatform;
    impl IpcPlatform for MockPlatform {
        fn has_permission_on_memory(
            &self,
            _base: *const u8,
            _len: usize,
            _is_write: bool,
            _caller: CallerAttributes,
        ) -> bool {
            true
        }

        fn custom_mpu_regions(&self, _handle: ServiceHandle) -> &[CustomMpuRegion] {
            &[]
        }
    }
    impl IpcProcessPlatform for MockPlatform {}

    struct MockProcess {
        handle: ServiceHandle,
    }

    impl IpcProcess for MockProcess {
        fn handle(&self) -> ServiceHandle {
            self.handle
        }

        fn get_vectors(&self) -> Option<&'static ServiceVectors> {
            None
        }

        fn version(&self) -> u32 {
            1
        }

        fn init_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
            &self,
            _platform: &P,
            _spm: &S,
        ) {
        }

        fn call_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
            &self,
            _platform: &P,
            _spm: &S,
            _msg: PsaMsg,
        ) -> Result<(), crate::StatusCode> {
            Ok(())
        }
    }

    #[test]
    fn test_spm_ipc_find_process() {
        static PLATFORM: MockPlatform = MockPlatform;
        let processes = [
            MockProcess {
                handle: ServiceHandle::Crypto,
            },
            MockProcess {
                handle: ServiceHandle::AttestationService,
            },
        ];
        let spm = SpmIpc::new(&PLATFORM, processes);

        assert_eq!(spm.find_process_index(ServiceHandle::Crypto), Some(0));
        assert_eq!(
            spm.find_process_index(ServiceHandle::AttestationService),
            Some(1)
        );
        assert_eq!(
            spm.find_process_index(ServiceHandle::InternalTrustedStorageService),
            None
        );
    }

    #[test]
    fn test_spm_ipc_version() {
        static PLATFORM: MockPlatform = MockPlatform;
        let processes = [MockProcess {
            handle: ServiceHandle::Crypto,
        }];
        let spm = SpmIpc::new(&PLATFORM, processes);

        assert_eq!(spm.version(ServiceHandle::Crypto), Some(1));
        assert_eq!(spm.version(ServiceHandle::AttestationService), None);
    }
}
