use m3::errors::Error;
use m3::io::LogFlags;
use m3::log;
use m3::mem::VirtAddr;
use m3::tiles::{Activity, ActivityArgs, ChildActivity, Tile};
use m3::time::{CycleDuration, CycleInstant, Duration};

#[macro_export]
macro_rules! create_data {
    ($num:expr, $ty:ty, $off:expr) => {{
        let mut input = m3::vec![];
        let mut expected_output = m3::vec![];
        for i in 0..$num {
            input.push(i as $ty);
            expected_output.push((i + $off) as $ty);
        }
        (input, expected_output)
    }};
}

pub fn create_activity<S: AsRef<str>>(name: S) -> Result<ChildActivity, Error> {
    let tile = Tile::get("compat")?;
    ChildActivity::new_with(tile, ActivityArgs::new(name.as_ref()))
}

pub fn compute_for(name: &str, duration: CycleDuration) {
    log!(LogFlags::Debug, "{}: computing for {:?}", name, duration);

    let end = CycleInstant::now().as_cycles() + duration.as_raw();
    while CycleInstant::now().as_cycles() < end {}
}

pub fn buffer_addr() -> VirtAddr {
    // TODO that's a bit of guess work here; at some point we might want to have an abstraction in
    // libm3 that manages our address space or so.
    let tile_desc = Activity::own().tile_desc();
    if tile_desc.has_virtmem() {
        VirtAddr::new(0x3000_0000)
    }
    else {
        VirtAddr::from(tile_desc.mem_offset() + tile_desc.mem_size() / 2)
    }
}
