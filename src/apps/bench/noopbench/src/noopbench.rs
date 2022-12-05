#![no_std]

use m3::errors::Error;
use m3::kif;
use m3::mem::MsgBuf;
use m3::println;
use m3::tcu;
use m3::tcu::EpId;
use m3::tiles::Activity;
use m3::time::Runner;
use m3::time::{CycleInstant, Profiler};

#[inline(always)]
fn send_msg<T>(msg_obj: T, sep: EpId, rep: EpId) -> Result<(), Error> {
    // let algn = std::mem::align_of_val(&msg_obj);
    // assert!(size <= MAX_MSG_SIZE);
    // assert!(algn <= cfg::PAGE_SIZE);
    let mut msg_buf = MsgBuf::borrow_def();
    msg_buf.set(msg_obj);
    tcu::TCU::send(
        sep,
        &msg_buf,
        0,
        rep
    )
}

#[inline(always)]
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


struct Tester(usize);

impl Runner for Tester {
    fn pre(&mut self) {
        let noop = kif::syscalls::Noop {
            opcode: kif::syscalls::Operation::NOOP.val,
        };
        send_msg(
            noop,
            tcu::FIRST_USER_EP + tcu::SYSC_SEP_OFF,
            tcu::FIRST_USER_EP + tcu::SYSC_REP_OFF,
        )
        .unwrap();
    }

    fn run(&mut self) {
        wait_for_rpl::<kif::DefaultReply>(tcu::FIRST_USER_EP + tcu::SYSC_REP_OFF, self.0)
            .unwrap();
    }
}

#[inline(never)]
fn noop_syscall(rbuf: usize) {
    let noop = kif::syscalls::Noop {
        opcode: kif::syscalls::Operation::NOOP.val,
    };
    send_msg(
        noop,
        tcu::FIRST_USER_EP + tcu::SYSC_SEP_OFF,
        tcu::FIRST_USER_EP + tcu::SYSC_REP_OFF,
    )
    .unwrap();
    wait_for_rpl::<kif::DefaultReply>(tcu::FIRST_USER_EP + tcu::SYSC_REP_OFF, rbuf).unwrap();
}

#[no_mangle]
pub fn main() -> i32 {

    let (rbuf_addr, size) = Activity::own().tile_desc().rbuf_std_space();
    println!("rbuf_addr: {:#x}, rbuf_size: {:#x}", rbuf_addr, size);

    let mut profiler = Profiler::default().warmup(50).repeats(1000);
    // let mut res = profiler.runner::<CycleInstant, _>(&mut Tester(rbuf_addr));
    let mut res = profiler.run::<CycleInstant, _>(|| {
        noop_syscall(rbuf_addr);
    });
    println!("{}", res);
    res.filter_outliers();
    println!("{}", res);

    0
}
