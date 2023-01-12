#![no_std]

use m3::{
    col::{String, ToString, Vec},
    errors::Error,
    format,
    io::{Read, Write},
    kif::{self, Perm},
    mem::MsgBuf,
    println,
    tcu::{self, EpId},
    tiles::Activity,
    time::{
        CycleDuration, CycleInstant, Duration, Profiler, Results, Runner, TimeDuration, TimeInstant,
    },
    vec,
    vfs::{FileMode, FileRef, GenericFile, OpenFlags, VFS},
};

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

fn bench_custom_noop_syscall(profiler: &Profiler) -> Results<CycleDuration> {
    let (rbuf, _) = Activity::own().tile_desc().rbuf_std_space();
    profiler.run::<CycleInstant, _>(|| {
        noop_syscall(rbuf);
    })
}

fn bench_m3_noop_syscall(profiler: &Profiler) -> Results<CycleDuration> {
    profiler.run::<CycleInstant, _>(|| {
        m3::syscalls::noop().unwrap();
    })
}

fn bench_tlb_insert(profiler: &Profiler) -> Results<CycleDuration> {
    let sample_addr = profiler as *const Profiler as usize;
    profiler.run::<CycleInstant, _>(|| {
        tcu::TCU::handle_xlate_fault(sample_addr, Perm::R);
    })
}

const STR_LEN: usize = 512 * 1024;

fn bench_m3fs_read(profiler: &Profiler) -> Results<TimeDuration> {
    let mut file = VFS::open("/new-file.txt", OpenFlags::CREATE | OpenFlags::RW).unwrap();
    let content: String = (0..STR_LEN).map(|_| "a").collect();
    write!(file, "{}", content).unwrap();

    let res = profiler.run::<TimeInstant, _>(|| {
        let _content = file.read_to_string().unwrap();
    });

    VFS::unlink("/new-file.txt").unwrap();
    res
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

fn bench_m3fs_write(profiler: &Profiler) -> Results<TimeDuration> {
    profiler.runner::<TimeInstant, _>(&mut WriteBenchmark::new())
}

fn bench_m3fs_meta(profiler: &Profiler) -> Results<TimeDuration> {
    profiler.run::<TimeInstant, _>(|| {
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

fn print_csv(data: Vec<(String, Vec<u64>)>) {
    if data.is_empty() {
        return;
    }
    let header = data
        .iter()
        .map(|column| format!("\"{}\"", column.0))
        .collect::<Vec<String>>()
        .join(",");
    println!("{}", header);
    let n_row = data[0].1.len();
    for r in 0..n_row {
        let row = data
            .iter()
            .map(|(_, d)| d[r].to_string())
            .collect::<Vec<String>>()
            .join(",");
        println!("{}", row);
    }
}

fn print_summary<T: Duration>(name: &str, mut res: Results<T>) {
    println!("\n\n{}:", name);
    println!("{}", res);
    res.filter_outliers();
    println!("filtered: {}", res);
}

fn _column<T: Duration>(name: &str, res: &Results<T>) -> (String, Vec<u64>) {
    (name.into(), res.times.iter().map(|t| t.as_raw()).collect())
}

#[no_mangle]
pub fn main() {
    VFS::mount("/", "m3fs", "m3fs").unwrap();
    let profiler = Profiler::default().warmup(50).repeats(500);

    let cnoop = bench_custom_noop_syscall(&profiler);
    let m3noop = bench_m3_noop_syscall(&profiler);
    let tlb = bench_tlb_insert(&profiler);
    let read = bench_m3fs_read(&profiler);
    let write = bench_m3fs_write(&profiler);
    let meta = bench_m3fs_meta(&profiler);

    print_csv(vec![
        _column("custom noop", &cnoop),
        _column("m3 noop", &m3noop),
        _column("tlb insert", &tlb),
        _column("m3fs read", &read),
        _column("m3fs write", &write),
        _column("m3fs meta", &meta),
    ]);

    print_summary("custom noop", cnoop);
    print_summary("m3 noop", m3noop);
    print_summary("tlb insert", tlb);
    print_summary("m3fs read", read);
    print_summary("m3fs write", write);
    print_summary("m3fs meta", meta);
}
