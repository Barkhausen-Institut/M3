#![no_std]

use m3::errors::Error;
use m3::io::Read;
use m3::io::Write;
use m3::vfs::{OpenFlags, VFS};
use m3::{env, format, println, vec};

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let filename = env::args()
        .nth(1)
        .expect(&format!("Usage: {} <file>", env::args().next().unwrap()));

    let mut file =
        VFS::open(filename, OpenFlags::R).expect(&format!("Unable to open {}", filename));

    println!("Contents of {}:", filename);
    let mut buf = vec![0u8; 512];
    loop {
        let count = file
            .read(&mut buf)
            .expect(&format!("Read of {} failed", filename));
        if count == 0 {
            break;
        }

        m3::io::stdout()
            .get_mut()
            .write_all(&buf[0..count])
            .unwrap();
    }

    Ok(())
}
