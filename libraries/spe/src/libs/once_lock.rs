use core::{
    cell::UnsafeCell,
    hint::spin_loop,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;

/// A no-std once-initialized value backed by atomics alone.
pub struct OnceLock<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

unsafe impl<T: Sync> Sync for OnceLock<T> {}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(UNINITIALIZED),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == INITIALIZED {
            // ### Safety: state == INITIALIZED guarantees value is initialized
            unsafe { Some((*self.value.get()).assume_init_ref()) }
        } else {
            None
        }
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        match self.state.compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // ### Safety: we hold the INITIALIZING state exclusively
                unsafe {
                    (*self.value.get()).write(value);
                }
                self.state.store(INITIALIZED, Ordering::Release);
                Ok(())
            }
            Err(_) => Err(value),
        }
    }
}
