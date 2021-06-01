#![no_std]

use m3::com::{recv_msg, RecvGate};
use m3::{println, reply_vmsg};

#[no_mangle]
pub fn main() -> i32 {
    let rgate = RecvGate::new_named("chan").expect("unable to get RecvGate chan");

    loop {
        let mut is = recv_msg(&rgate).expect("receive failed");
        let val = is.pop::<u32>().expect("unable to get value");
        println!("got message {}", val);
        reply_vmsg!(is, 0).expect("reply failed");
    }
}
