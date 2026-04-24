use crate::{ psa::psa_call::PsaMsg};

pub struct Info {
    pub version: u32,
}

pub trait Service {
    fn info(&self) -> Info;
    fn call(&self, msg: PsaMsg);
    fn init(&mut self);
    fn deinit(&mut self);
}
