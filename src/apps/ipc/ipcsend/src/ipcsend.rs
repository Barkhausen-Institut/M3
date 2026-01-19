#![no_std]

#[allow(unused_extern_crates)]
extern crate m3;

use m3::errors::Error;

#[no_mangle]
pub fn main() -> Result<(), Error> {
    /*
    // We get the named send gate, which has been configured in our boot XML.
    let send_gate = todo!().expect("unable to get SendGate chan");

    // We need to set a message size large enough for the TCU header and the reply payload.
    let msg_order = math::next_log2(64);
    let buf_order = msg_order;
    // We create a receive gate, which receives the replies to our messages.
    let reply_gate = todo!().expect("unable to create RecvGate");

    for i in 0..64 {
        let payload: u32 = i;
        // We send the payload to the other side and wait for the reply.
        let mut gate_stream = todo!().expect("send/receive failed");
        // Unmarshall the reply.
        let reply = todo!().expect("unmarshalling failed");
        println!("{}", reply);
    }
    */

    Ok(())
}
