use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

#[derive(Debug)]
#[repr(u8)]
pub enum OnceLockState {
    Uninitialized,
    Initializing,
    Initialized,
}

/// A no-std once-initialized value backed by atomics.
pub struct OnceLock<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// # Safety:
// 1. `Send` is required because the value `T` might be created on one thread
//    and dropped on another when the `OnceLock` is dropped.
// 2. `Sync` is required because multiple threads can access `&T` (via `get`)
//    simultaneously once initialization is complete.
unsafe impl<T: Sync + Send> Sync for OnceLock<T> {}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(OnceLockState::Uninitialized as u8),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Returns a reference to the value if it has been initialized.
    pub fn try_get(&self) -> Result<&T, OnceLockState> {
        // We use Acquire ordering to ensure that if we see INITIALIZED,
        // all memory writes performed by the initializing thread (the value write)
        // are visible to this thread.
        let state = self.state.load(Ordering::Acquire);

        if state == OnceLockState::Initializing as u8 {
            return Err(OnceLockState::Initializing);
        }

        if state == OnceLockState::Initialized as u8 {
            // # Safety:
            // 1. The state is INITIALIZED, which means a successful `set` call
            //    has completed writing to the value.
            // 2. We used Acquire ordering to load the state, synchronizing with
            //    the Release store in `set`, making the initialized value visible.
            // 3. We return a shared reference `&T` tied to the lifetime of `&self`.
            //    The value is never mutated or dropped as long as the `OnceLock` exists.
            unsafe { Ok((*self.value.get()).assume_init_ref()) }
        } else {
            Err(OnceLockState::Uninitialized)
        }
    }

    /// Sets the value of the lock. Returns `Err(value)` if already initialized or initializing.
    pub fn try_set(&self, value: T) -> Result<(), T> {
        // We use compare_exchange to transition from UNINITIALIZED to INITIALIZING.
        // This acts as a mutual exclusion lock for the initialization phase.
        match self.state.compare_exchange(
            OnceLockState::Uninitialized as u8,
            OnceLockState::Initializing as u8,
            Ordering::AcqRel, // Acquire to see previous state, Release to signal INITIALIZING
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // # Safety:
                // Having successfully transitioned the state to INITIALIZING,
                // we have exclusive mutable access to the inner UnsafeCell.
                unsafe {
                    (*self.value.get()).write(value);
                }

                // Use Release ordering to ensure the write to `value` above happens
                // before the state becomes INITIALIZED. This synchronizes with
                // the Acquire load in `get`.
                self.state
                    .store(OnceLockState::Initialized as u8, Ordering::Release);
                Ok(())
            }
            Err(_) => Err(value),
        }
    }
}

impl<T> Drop for OnceLock<T> {
    fn drop(&mut self) {
        // We use Relaxed here because we have unique access (&mut self),
        // so no other threads can be accessing the lock.
        if *self.state.get_mut() == OnceLockState::Initialized as u8 {
            // # Safety:
            // The state is INITIALIZED, so the value is valid.
            // We are in `drop`, so the value will never be accessed again.
            unsafe {
                self.value.get_mut().assume_init_drop();
            }
        }
    }
}
