#![no_std]

use m3::com::{recv_msg, RecvGate};
use m3::reply_vmsg;

#[no_mangle]
pub fn main() -> i32 {
    let mut rgate = RecvGate::new_named("chan").expect("unable to get RecvGate chan");
    rgate.activate().expect("unable to activate RecvGate");

    loop {
        let mut is = recv_msg(&rgate).expect("receive failed");
        let val = is.pop::<u32>().expect("unable to get value");
        m3::println!("got message {}", val);
        reply_vmsg!(is, 0).expect("reply failed");
    }
}
