use crate::psa::psa_call::PsaMsg;

pub struct Info {
    pub version: u32,
}

pub trait Service {
    fn info(&self) -> Info;
    fn call(&self, msg: PsaMsg) -> Result<(), psa_interface::StatusCode>;
    fn init(&mut self) -> Result<(), psa_interface::StatusCode>;
    fn deinit(&mut self) -> Result<(), psa_interface::StatusCode>;
}
