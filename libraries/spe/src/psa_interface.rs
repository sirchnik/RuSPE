#[derive(Clone, Copy)]
#[repr(C)]
pub enum PsaHandle {
    Crypto,
    SecureStorage,
    Attestation,
}
// TODO enums
pub type PsaStatus = i32;

#[repr(C)]
pub struct PsaInVec {
    pub base: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct PsaOutVec {
    pub base: *mut u8,
    pub len: usize,
}

///
///  31           30-28   27    26-24  23-20   19     18-16   15-0
/// +------------+-----+------+-------+-----+-------+-------+------+
/// | NS vector  |     | NS   | invec |     | NS    | outvec| type |
/// | descriptor | Res | invec| number| Res | outvec| number|      |
/// +------------+-----+------+-------+-----+-------+-------+------+
///
/// Res: Reserved.
///
#[derive(Clone, Copy)]
#[repr(C)]
pub struct VectorDescriptor(u32);

impl VectorDescriptor {
    pub const NS_VEC_DESC_BIT: u32 = 0x8000_0000;

    /// Creates a new descriptor from components, handling the masks and offsets.
    pub fn new(r#type: i16, in_len: u8, in_ns: bool, out_len: u8, out_ns: bool) -> Self {
        let mut val = (r#type as u16 as u32) & 0xFFFF;
        val |= ((in_len as u32) << 24) & 0x0700_0000; // IN_LEN_MASK
        val |= ((out_len as u32) << 16) & 0x0007_0000; // OUT_LEN_MASK
        if in_ns {
            val |= 0x0800_0000; // IN_NS_MASK
        }
        if out_ns {
            val |= 0x0008_0000; // OUT_NS_MASK
        }
        Self(val)
    }

    pub fn unpack_type(&self) -> i32 {
        (self.0 as u16 as i16) as i32
    }

    /// Port of PARAM_HAS_IOVEC
    /// Checks if any bits outside the type mask are set.
    pub fn has_iovec(&self) -> bool {
        // Equivalent to (ctrl_param) != (uint32_t)PARAM_UNPACK_TYPE(ctrl_param)
        (self.0 & !0xFFFF) != 0
    }

    pub fn set_ns_vec(&mut self) {
        self.0 |= Self::NS_VEC_DESC_BIT;
    }

    pub fn is_ns_vec(&self) -> bool {
        (self.0 & Self::NS_VEC_DESC_BIT) != 0
    }

    pub fn is_ns_ivec(&self) -> bool {
        (self.0 & 0x0800_0000) != 0
    }

    pub fn is_ns_ovec(&self) -> bool {
        (self.0 & 0x0008_0000) != 0
    }

    /// Getters for lengths (Port of PARAM_UNPACK_IN_LEN/OUT_LEN)
    pub fn in_len(&self) -> usize {
        ((self.0 >> 24) & 0x7) as usize
    }

    pub fn out_len(&self) -> usize {
        ((self.0 >> 16) & 0x7) as usize
    }
}
