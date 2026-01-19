#![no_std]

#[allow(unused_extern_crates)]
extern crate m3;

use m3::errors::Error;

#[no_mangle]
pub fn main() -> Result<(), Error> {
    /*
    // We get the named receive gate, which has been configured in our boot XML.
    let recv_gate = todo!().expect("unable to get RecvGate chan");

    loop {
        // Receive one message.
        let mut gate_stream = todo!().expect("receive failed");
        // Unmarshall the message.
        let argument = todo!().expect("unable to get value");
        let result = 100 * argument + 42;
        // Reply with the result.
        todo!().expect("reply failed");
    }
    */

    Ok(())
}
