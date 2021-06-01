#![no_std]

use m3::com::{recv_reply, RGateArgs, RecvGate, SendGate};
use m3::send_vmsg;
use m3::util::math;

#[no_mangle]
pub fn main() -> i32 {
    let sgate = SendGate::new_named("chan").expect("unable to get SendGate chan");

    let msg_size = 64;
    let buf_size = msg_size * sgate.credits().expect("unable to get credits");
    let reply_gate = RecvGate::new_with(
        RGateArgs::default()
            .order(math::next_log2(buf_size as usize))
            .msg_order(math::next_log2(msg_size as usize)),
    )
    .expect("unable to create RecvGate");

    let mut sends = 0;
    let mut replies = 0;
    while replies < 64 {
        if sends < 64 && sgate.can_send().unwrap() {
            // make sure the receiver can reply to us
            while let Ok(reply) = reply_gate.fetch() {
                reply_gate.ack_msg(reply).expect("ACK failed");
                replies += 1;
            }

            send_vmsg!(sgate, &reply_gate, sends).expect("send failed");
            sends += 1;
        }
        else {
            recv_reply(&reply_gate, Some(&sgate)).expect("receive failed");
            replies += 1;
        }
    }
    0
}
