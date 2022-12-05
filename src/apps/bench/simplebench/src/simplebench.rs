
#![no_std]

use m3::cpu;
use m3::tcu;
use m3::time::{CycleInstant, Profiler};
use m3::println;


fn bench<F: FnMut()>(p: &Profiler, name: &str, f: F) {
    let mut res = p.run::<CycleInstant, _>(f);
    res.filter_outliers();
    println!("{}: {}", name, res);
}

#[no_mangle]
pub fn main() {
    let p = Profiler::default().warmup(50).repeats(1000);

    bench(&p, "mmio cpu::write8b", || unsafe {
        cpu::write8b(tcu::MMIO_ADDR, 5u64);
    });
    bench(&p ,"mmio volatile_write", || unsafe {
        (tcu::MMIO_ADDR as *mut u64).write_volatile(5u64);
    });
    bench(&p,"mmio write", || unsafe {
        (tcu::MMIO_ADDR as *mut u64).write(5u64);
    });
    bench(&p,"mmio dereference", || unsafe {
        *(tcu::MMIO_ADDR as *mut u64) = 5u64;
    });

    let mut a: u64 = 3;

    bench(&p, "stack cpu::write8b", || unsafe {
        cpu::write8b(&mut a as *mut u64 as usize, 5u64);
    });
    bench(&p, "stack volatile_write", || unsafe {
        (&mut a as *mut u64).write_volatile(5u64);
    });
    bench(&p, "stack write", || unsafe {
        (&mut a as *mut u64).write(5u64);
    });
    bench(&p, "stack dereference", || unsafe {
        *(&mut a as *mut u64) = 5u64;
    });
}
