#![no_std]

use m3::errors::Error;

#[no_mangle]
pub fn main() -> Result<(), Error> {
    /*

    // Read all program arguments into a single input string:
    let input = todo!();

    println!("Original input:     {}", input);
    let input = input.as_bytes();

    // Create a new pipes session.

    const MEM_SIZE: u64 = 32;
    let in_mem = MemCap::new(MEM_SIZE, Perm::RW).expect("failed to get memory capability");
    let out_mem = MemCap::new(MEM_SIZE, Perm::RW).expect("failed to get memory capability");

    // Create two indirect pipes using the memory capabilities above.

    // Get the tile capability and use it to create a new child activity:
    let act = todo!();

    // Create a new streaming accelerator from the activity. Set the tee parameter to false.

    // Attach the correct pipe reader/writer to the streaming accelerator input/output.

    let _act = act.start().expect("failed to start accelerator");

    // Get the other reader/writer ends of the two pipes:
    let mut write_end = todo!();
    let mut read_end = todo!();

    write_end
        .set_blocking(false)
        .expect("could not set pipe end non-blocking");
    write_end
        .set_blocking(false)
        .expect("could not set pipe end non-blocking");

    let mut output = vec![0; input.len()];
    let mut in_pos = 0;
    let mut out_pos = 0;
    while out_pos < output.len() {
        // Try to write input data if there is any data left:
        match write_end.write(todo!()) {
            Err(e) if e.code() == Code::WouldBlock => {},
            r => {
                let number_of_written_bytes = r.expect("writing input failed");
                todo!("use number_of_written_bytes");
                if in_pos >= input.len() {
                    in_pipe.close_writer();
                }
            },
        }

        // Try to read into output:
        match read_end.read(todo!()) {
            Err(e) if e.code() == Code::WouldBlock => {},
            r => {
                let number_of_read_bytes = r.expect("reading output failed");
                todo!("use number_of_read_bytes");
                continue;
            },
        }

        OwnActivity::sleep().expect("could not wait for next message");
    }

    println!("Transformed output: {}", &String::from_utf8_lossy(&output));

    */

    Ok(())
}
