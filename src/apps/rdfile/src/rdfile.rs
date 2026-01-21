#![no_std]

use m3::errors::Error;
use m3::io::Write;
use m3::vec;

#[no_mangle]
pub fn main() -> Result<(), Error> {
    // Create an empty vector to store the read file contents.
    let buf = vec![0u8; 512];
    let count = 0;
    // Write the binary data directly to STDOUT.
    m3::io::stdout()
        .get_mut()
        .write_all(&buf[0..count])
        .unwrap();

    Ok(())
}
