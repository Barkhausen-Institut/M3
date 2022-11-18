
#![no_std]

use m3::println;
use m3::time::{CycleInstant, TimeInstant, Profiler};
use m3::syscalls;


#[no_mangle]
pub fn main() -> i32 {
    let mut profiler = Profiler::default().repeats(1000);
    println!("{}", profiler.run::<CycleInstant, _>(|| {
        syscalls::noop().unwrap();
    }));
    println!("{}", profiler.run::<TimeInstant, _>(|| {
        syscalls::noop().unwrap();
    }));

    0
}