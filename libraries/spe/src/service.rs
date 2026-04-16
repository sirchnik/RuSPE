use crate::psa_interface::{PsaInVec, PsaOutVec};

pub struct Info {
    pub version: u32,
}

pub trait Service {
    fn info(&self) -> Info;
    fn call(&self, ctrl_param: u32, in_vec: *const PsaInVec, out_vec: *mut PsaOutVec);
    fn init(&mut self);
    fn deinit(&mut self);
}
