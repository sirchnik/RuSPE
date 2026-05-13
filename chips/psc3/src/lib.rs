#![no_std]

mod cmse;
pub mod platform;
pub mod security;

pub use platform::{Psc3AttestPlatform, Psc3SecPlatform};
pub use security::configure_security;
