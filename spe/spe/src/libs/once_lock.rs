// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

#[derive(Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering as StdOrdering};
    use std::sync::Arc;

    #[test]
    fn try_get_uninitialized_returns_err() {
        let lock = OnceLock::<u32>::new();
        assert!(matches!(lock.try_get(), Err(OnceLockState::Uninitialized)));
    }

    #[test]
    fn try_set_then_try_get() {
        let lock = OnceLock::new();
        assert!(lock.try_set(42u32).is_ok());
        assert_eq!(lock.try_get(), Ok(&42));
    }

    #[test]
    fn double_set_returns_value_back() {
        let lock = OnceLock::new();
        assert!(lock.try_set(1u32).is_ok());
        assert_eq!(lock.try_set(2u32), Err(2));
        // Original value unchanged.
        assert_eq!(lock.try_get(), Ok(&1));
    }

    #[test]
    fn drop_calls_destructor() {
        static DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

        #[derive(Debug)]
        struct DropCounter;
        impl Drop for DropCounter {
            fn drop(&mut self) {
                DROP_COUNT.fetch_add(1, StdOrdering::Relaxed);
            }
        }

        DROP_COUNT.store(0, StdOrdering::Relaxed);
        {
            let lock = OnceLock::new();
            lock.try_set(DropCounter).unwrap();
        }
        assert_eq!(DROP_COUNT.load(StdOrdering::Relaxed), 1);
    }

    #[test]
    fn drop_without_set_is_safe() {
        let _lock = OnceLock::<std::string::String>::new();
        // Should not panic or UB on drop.
    }

    #[test]
    fn concurrent_set_only_one_wins() {
        let lock = Arc::new(OnceLock::new());
        let barrier = Arc::new(std::sync::Barrier::new(8));

        let threads: std::vec::Vec<_> = (0..8u32)
            .map(|i| {
                let lock = Arc::clone(&lock);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    lock.try_set(i)
                })
            })
            .collect();

        let results: std::vec::Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(ok_count, 1);

        // The stored value must match the winner.
        let winner = results
            .iter()
            .enumerate()
            .find_map(|(i, r)| if r.is_ok() { Some(i as u32) } else { None })
            .unwrap();
        assert_eq!(lock.try_get(), Ok(&winner));
    }

    #[test]
    fn try_get_after_set_is_stable() {
        let lock = OnceLock::new();
        lock.try_set("hello").unwrap();
        for _ in 0..100 {
            assert_eq!(lock.try_get(), Ok(&"hello"));
        }
    }
}
