use m3::errors::Code;
use m3::serialize::{Deserialize, Serialize};

pub type Value = i32;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
#[repr(C)]
pub enum ChildReq {
    GetBoard,
    GetLog(Value),
    Play(Value),
    Trojan(Value),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
#[repr(C)]
pub struct ChildReply {
    pub res: Code,
    pub val: Value,
}

#[allow(dead_code)]
impl ChildReply {
    pub fn new(res: Code) -> Self {
        Self::new_with_val(res, 0)
    }

    pub fn new_with_val(res: Code, val: Value) -> Self {
        Self { res, val }
    }
}
