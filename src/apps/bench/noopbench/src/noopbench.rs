#![no_std]

use m3::errors::Error;
use m3::io::{Read, Write};
use m3::kif;
use m3::kif::Perm;
use m3::mem::MsgBuf;
use m3::println;
use m3::tcu;
use m3::tcu::EpId;
use m3::tiles::Activity;
use m3::time::{CycleInstant, Profiler, Runner, TimeInstant, Instant};
use m3::vfs::{FileRef, GenericFile, OpenFlags, VFS, FileMode};
use m3::col::String;

fn wait_for_rpl<T>(rep: EpId, rcv_buf: usize) -> Result<&'static T, Error> {
    loop {
        if let Some(off) = tcu::TCU::fetch_msg(rep) {
            let msg = tcu::TCU::offset_to_msg(rcv_buf, off);
            let rpl = msg.get_data::<kif::DefaultReply>();
            tcu::TCU::ack_msg(rep, off)?;
            return match rpl.error {
                0 => Ok(msg.get_data::<T>()),
                e => Err((e as u32).into()),
            };
        }
    }
}

fn noop_syscall(rbuf: usize) {
    let mut msg = MsgBuf::borrow_def();
    msg.set(kif::syscalls::Noop {
        opcode: kif::syscalls::Operation::NOOP.val,
    });
    tcu::TCU::send(
        tcu::FIRST_USER_EP + tcu::SYSC_SEP_OFF,
        &msg,
        0,
        tcu::FIRST_USER_EP + tcu::SYSC_REP_OFF,
    )
    .unwrap();
    wait_for_rpl::<()>(tcu::FIRST_USER_EP + tcu::SYSC_REP_OFF, rbuf).unwrap();
}

fn bench<T: Instant, F: FnMut()>(profiler: &Profiler, name: &str, f: F) {
    let mut res = profiler.run::<T, _>(f);
    println!("\n\n{}: {:?}", name, res);
    println!("{}: {}", name, res);
    res.filter_outliers();
    println!("{} filtered: {}", name, res);
}

fn bench_custom_noop_syscall(profiler: &Profiler) {
    let (rbuf, _) = Activity::own().tile_desc().rbuf_std_space();
    bench::<CycleInstant, _>(profiler, "custom noop", || {
        noop_syscall(rbuf);
    })
}

fn bench_m3_noop_syscall(profiler: &Profiler) {
    bench::<CycleInstant, _>(profiler, "m3 noop", || {
        m3::syscalls::noop().unwrap();
    })
}

fn bench_tlb_insert(profiler: &Profiler) {
    let sample_addr = profiler as *const Profiler as usize;
    bench::<CycleInstant, _>(profiler, "tlb insert", || {
        tcu::TCU::handle_xlate_fault(sample_addr, Perm::R);
    })
}

const STR_LEN: usize = 512 * 1024;

fn bench_m3fs_read(profiler: &Profiler) {
    let mut file = VFS::open("/new-file.txt", OpenFlags::CREATE | OpenFlags::RW).unwrap();
    let content: String = (0..STR_LEN).map(|_| "a").collect();
    write!(file, "{}", content).unwrap();

    bench::<TimeInstant, _>(profiler, "m3fs read", || {
        let _content = file.read_to_string().unwrap();
    });

    VFS::unlink("/new-file.txt").unwrap();
}

struct WriteBenchmark {
    file: FileRef<GenericFile>,
    content: String,
}

impl WriteBenchmark {
    fn new() -> WriteBenchmark {
        WriteBenchmark {
            file: VFS::open("/bla", OpenFlags::CREATE).unwrap(),
            content: (0..STR_LEN).map(|_| "a").collect(),
        }
    }
}

impl Runner for WriteBenchmark {
    fn pre(&mut self) {
        self.file = VFS::open("/new-file.txt", OpenFlags::CREATE | OpenFlags::W).unwrap();
    }

    fn run(&mut self) {
        write!(self.file, "{}", self.content).unwrap();
    }

    fn post(&mut self) {
        VFS::unlink("/new-file.txt").unwrap();
    }
}

fn bench_m3fs_write(profiler: &Profiler) {
    let mut res = profiler.runner::<TimeInstant, _>(&mut WriteBenchmark::new());
    let name = "m3fs write";
    println!("\n\n{}: {:?}", name, res);
    println!("{}: {}", name, res);
    res.filter_outliers();
    println!("{} filtered: {}", name, res);
}

fn bench_m3fs_meta(profiler: &Profiler) {
    bench::<TimeInstant, _>(profiler, "m3fs meta", || {
        VFS::mkdir("/new-dir", FileMode::from_bits(0o755).unwrap()).unwrap();
        let _ = VFS::open("/new-dir/new-file", OpenFlags::CREATE).unwrap();
        VFS::link("/new-dir/new-file", "/new-link").unwrap();
        VFS::rename("/new-link", "/new-blink").unwrap();
        let _ = VFS::stat("/new-blink").unwrap();
        VFS::unlink("/new-blink").unwrap();
        VFS::unlink("/new-dir/new-file").unwrap();
        VFS::rmdir("/new-dir").unwrap();
    })
}

#[no_mangle]
pub fn main() {
    VFS::mount("/", "m3fs", "m3fs").unwrap();
    let profiler = Profiler::default().warmup(50).repeats(500);
    bench_custom_noop_syscall(&profiler);
    bench_m3_noop_syscall(&profiler);
    bench_tlb_insert(&profiler);
    bench_m3fs_read(&profiler);
    bench_m3fs_write(&profiler);
    bench_m3fs_meta(&profiler);
}
