// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
pub struct Mutex<T> {
    lock: AtomicBool,
    value: UnsafeCell<T>,
}

// Soundness: T must be Send because Mutex allows transferring T
// to another thread that acquires the lock.
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            lock: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Primary entry point: Provides &mut T to the closure if the lock is free.
    pub fn try_lock<R>(&self, f: impl FnOnce(&mut T) -> R) -> Result<R, ()> {
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // # Safety
            // We have exclusive access via the atomic flag.
            let result = unsafe { f(&mut *self.value.get()) };

            self.lock.store(false, Ordering::Release);
            Ok(result)
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Arc;

    #[test]
    fn try_lock_provides_mutable_access() {
        let m = Mutex::new(0u32);
        let result = m.try_lock(|v| {
            *v = 42;
        });
        assert!(result.is_ok());
        assert_eq!(m.try_lock(|v| *v), Ok(42));
    }

    #[test]
    fn try_lock_returns_closure_result() {
        let m = Mutex::new(10u32);
        let result = m.try_lock(|v| *v + 5);
        assert_eq!(result, Ok(15));
    }

    #[test]
    fn try_lock_fails_when_already_held() {
        let m = Arc::new(Mutex::new(()));
        let m2 = Arc::clone(&m);

        // Hold the lock from another thread while we try to acquire it.
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b2 = Arc::clone(&barrier);

        let handle = std::thread::spawn(move || {
            m2.try_lock(|_| {
                b2.wait(); // signal: lock is held
                b2.wait(); // wait for main thread to finish its attempt
            })
            .unwrap();
        });

        barrier.wait(); // wait until lock is held
        let result = m.try_lock(|_| ());
        assert!(result.is_err());
        barrier.wait(); // release the spawned thread
        handle.join().unwrap();
    }

    #[test]
    fn lock_is_released_after_closure() {
        let m = Mutex::new(1u32);
        m.try_lock(|v| *v = 2).unwrap();
        // Lock should be free again.
        assert_eq!(m.try_lock(|v| *v), Ok(2));
    }

    #[test]
    fn concurrent_mutations_are_serialized() {
        let m = Arc::new(Mutex::new(0u32));
        let threads: std::vec::Vec<_> = (0..8)
            .map(|_| {
                let m = Arc::clone(&m);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        while m.try_lock(|v| *v += 1).is_err() {
                            std::hint::spin_loop();
                        }
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(m.try_lock(|v| *v), Ok(8000));
    }
}
