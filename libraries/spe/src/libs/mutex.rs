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

    /// Sets the value if the lock is available.
    pub fn try_set(&self, value: T) -> Result<(), ()> {
        self.try_lock(|inner| *inner = value)
    }

    /// Returns a copy of the value if the lock is available.
    pub fn try_get(&self) -> Option<T>
    where
        T: Copy,
    {
        self.try_lock(|inner| *inner).ok()
    }

    /// Replaces the value and returns the old one if the lock is available.
    pub fn try_replace(&self, value: T) -> Result<T, ()> {
        self.try_lock(|inner| core::mem::replace(inner, value))
    }

    /// Takes the value, leaving Default::default() in its place.
    pub fn try_take(&self) -> Option<T>
    where
        T: Default,
    {
        self.try_lock(|inner| core::mem::take(inner)).ok()
    }
}
