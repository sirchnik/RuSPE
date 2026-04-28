use core::{
    cell::Cell,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
pub struct InterruptUnsafeMutex<T> {
    value: T,
    lock: AtomicBool,
}

unsafe impl<T> Sync for InterruptUnsafeMutex<T> {}

impl<T> InterruptUnsafeMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            value,
            lock: AtomicBool::new(false),
        }
    }

    pub fn lock<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        // Spin until we acquire the lock
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // Spin-wait until the lock is free
        }
        let result = f(&self.value);
        self.lock.store(false, Ordering::SeqCst);
        result
    }
}

impl<T> InterruptUnsafeMutex<Cell<T>> {
    pub fn get(&self) -> T
    where
        T: Copy,
    {
        self.lock(|cell| cell.get())
    }

    pub fn take(&self) -> T
    where
        T: Default,
    {
        self.lock(|cell| cell.take())
    }

    pub fn set(&self, value: T) {
        self.lock(|cell| cell.set(value));
    }
}
