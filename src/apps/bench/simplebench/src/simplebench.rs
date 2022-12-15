#![no_std]

use m3::cpu;
use m3::println;
use m3::tcu;
use m3::time::{CycleInstant, Profiler};

#[allow(unused)]
fn bench<F: FnMut()>(p: &Profiler, name: &str, f: F) {
    let mut res = p.run::<CycleInstant, _>(f);
    res.filter_outliers();
    println!("{}: {}", name, res);
}

use core::arch::asm;

#[allow(unused)]
fn bench_writes() {
    let p = Profiler::default().warmup(50).repeats(1000);

    bench(&p, "mmio cpu::write8b", || unsafe {
        cpu::write8b(tcu::MMIO_ADDR, 5u64);
    });
    bench(&p, "mmio volatile_write", || unsafe {
        (tcu::MMIO_ADDR as *mut u64).write_volatile(5u64);
    });
    bench(&p, "mmio write", || unsafe {
        (tcu::MMIO_ADDR as *mut u64).write(5u64);
    });
    bench(&p, "mmio dereference", || unsafe {
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

#[allow(unused)]
fn write_to_stack() {
    let mut a: u64 = 3;
    let val1: u64 = 0xbadc0ffee0ddf00c;
    let val2: u64 = 0xbadc0ffee0ddf00d;
    let addr: usize = &mut a as *mut u64 as usize;
    unsafe {
        asm!("sd {0}, ({1})", in(reg) val1, in(reg) addr, options(nostack));
        asm!("sd {0}, ({1})", in(reg) val2, in(reg) addr, options(nostack));
    }
}

#[allow(unused)]
#[inline(always)]
fn bench_sd_instruction() {
    let mut a: u64 = 3;
    let val: u64 = 0xbadc0ffee0ddf00d;
    let addr: usize = &mut a as *mut u64 as usize;
    let p = Profiler::default().warmup(0).repeats(100);
    for _ in 0..100 {
        unsafe {
            asm!("sd {0}, ({1})", in(reg) val, in(reg) addr, options(nostack));
        }
    }
}

#[allow(unused)]
#[inline(always)]
fn bench_dereference() {
    let mut a: u64 = 3;
    let val: u64 = 0xbadc0ffee0ddf00d;
    for _ in 0..100 {
        unsafe {
            *(&mut a as *mut u64) = val;
        }
    }
    unsafe {
        *(&mut a as *mut u64) = 0xbadc0ffee0ddf00c;
    }
    let p = Profiler::default().warmup(50).repeats(1000);
    bench(&p, "stack dereference", || unsafe {
        *(&mut a as *mut u64) = val;
    })
}

#[allow(unused)]
#[inline(always)]
fn bench_nothing() {
    let p = Profiler::default().warmup(50).repeats(1000);
    bench(&p, "empty function", ||{});
}

#[no_mangle]
pub fn main() {
    bench_nothing();
    bench_writes();
}
