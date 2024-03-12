use num_enum::IntoPrimitive;

use crate::errors::{Code, Error};
use crate::kif::Perm;
use crate::mem::VirtAddr;

#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(usize)]
pub enum MemType {
    TCU,
    TCUEPs,
    Environment,
    StdRecvBuf,
    Custom,
}

pub fn mmap_tcu(
    fd: libc::c_int,
    addr: VirtAddr,
    size: usize,
    ty: MemType,
    perm: Perm,
) -> Result<(), Error> {
    let mut prot = 0;
    if perm.contains(Perm::R) {
        prot |= libc::PROT_READ;
    }
    if perm.contains(Perm::W) {
        prot |= libc::PROT_WRITE;
    }

    let base = unsafe {
        libc::mmap(
            addr.as_local() as *mut libc::c_void,
            size,
            prot,
            libc::MAP_SHARED | libc::MAP_FIXED | libc::MAP_SYNC,
            fd,
            (ty as libc::off_t) << 12,
        )
    };
    match base {
        x if x as usize == addr.as_local() => Ok(()),
        _ => Err(Error::new(Code::Unspecified)),
    }
}

pub fn munmap(addr: VirtAddr, size: usize) {
    unsafe {
        libc::munmap(addr.as_local() as *mut libc::c_void, size);
    }
}
