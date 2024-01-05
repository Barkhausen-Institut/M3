use m3::errors::Code;
use m3::serialize::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
#[repr(C)]
pub enum ChildReq {
    Get,
    Set(u8),
    Attack(u8),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
#[repr(C)]
pub struct ChildReply {
    pub res: Code,
    pub val: u8,
}

#[allow(dead_code)]
impl ChildReply {
    pub fn new(res: Code) -> Self {
        Self::new_with_val(res, 0)
    }

    pub fn new_with_val(res: Code, val: u8) -> Self {
        Self { res, val }
    }
}
