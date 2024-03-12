use crate::cfg;
use crate::kif;
use crate::mem::VirtAddr;
use crate::tcu::ActId;

use super::tcu_fd;

// this is defined in linux/drivers/tcu/tcu.cc
const IOCTL_WAIT_ACT: u64 = 0x80087101;
const IOCTL_RGSTR_ACT: u64 = 0x40087102;
const IOCTL_TLB_INSERT: u64 = 0x40087103;
const IOCTL_UNREG_ACT: u64 = 0x40087104;
const IOCTL_NOOP: u64 = 0x00007105;

fn ioctl(magic_number: u64) {
    unsafe {
        let res = libc::ioctl(tcu_fd(), magic_number);
        if res != 0 {
            libc::perror(0 as *const u8);
            panic!("ioctl call {} failed with error {}", magic_number, res);
        }
    }
}

fn ioctl_read<T: Default>(magic_number: u64) -> T {
    let mut arg: T = T::default();
    unsafe {
        let res = libc::ioctl(tcu_fd(), magic_number, &mut arg as *mut _);
        if res != 0 {
            libc::perror(0 as *const u8);
            panic!("ioctl call {} failed with error {}", magic_number, res);
        }
    }
    arg
}

fn ioctl_plain(magic_number: u64, arg: usize) {
    unsafe {
        let res = libc::ioctl(tcu_fd(), magic_number, arg);
        if res != 0 {
            libc::perror(0 as *const u8);
            panic!("ioctl call {} failed with error {}", magic_number, res);
        }
    }
}

pub fn wait_act() -> ActId {
    ioctl_read(IOCTL_WAIT_ACT)
}

pub fn register_act(id: ActId) {
    ioctl_plain(IOCTL_RGSTR_ACT, id as usize);
}

pub fn tlb_insert_addr(virt: VirtAddr, perm: u8) {
    // touch the memory first to cause a page fault, because the TCU-TLB miss handler in the Linux
    // kernel cannot deal with the request if the page isn't mapped.
    let virt_ptr = virt.as_mut_ptr::<u8>();
    if (perm & kif::Perm::W.bits() as u8) != 0 {
        unsafe { virt_ptr.write_volatile(0) }
    }
    else {
        let _val = unsafe { virt_ptr.read_volatile() };
    }

    let arg = virt.as_local() & !cfg::PAGE_MASK | perm as usize;
    ioctl_plain(IOCTL_TLB_INSERT, arg);
}

pub fn unregister_act(id: ActId, status: i32) {
    ioctl_plain(IOCTL_UNREG_ACT, id as usize | (status as usize) << 16);
}

pub fn noop() {
    ioctl(IOCTL_NOOP);
}
