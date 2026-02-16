#![no_std]

use m3::errors::Error;

#[no_mangle]
pub fn main() -> Result<(), Error> {
    /*
    use m3::client::ClientSession;
    use m3::col::String;
    use m3::com::MemGate;
    use m3::{println, vec};

    // Get the client session that was configured in the boot XML.
    let session = ClientSession::new("sessions").expect("failed to get session");

    let crd = todo!("obtain memory capability via session");

    // Bind the memory capability to a memory gate at our own TCU.
    let mem = MemGate::new_bind(crd.start()).expect("failed to activate memory gate");

    // Read and print the data stored behind the memory capability.
    let mut data = vec![0; 12];
    mem.read(&mut data, 0)
        .expect("failed to read data via memory gate");
    println!(
        "Data from server (via memory capability): {}",
        String::from_utf8_lossy(&data)
    );
    */

    Ok(())
}
