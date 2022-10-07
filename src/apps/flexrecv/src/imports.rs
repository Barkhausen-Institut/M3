#[cfg(not(feature = "std"))]
mod m3types {
    pub use m3::boxed::Box;
    pub use m3::col::{String, Vec};
    pub use m3::sync::Arc;
    pub use m3::time::TimeDuration as Duration;
    pub use m3::{println, vec};

    pub fn sleep(duration: Duration) {
        m3::tiles::Activity::own().sleep_for(duration).unwrap();
    }
}

#[cfg(feature = "std")]
mod stdtypes {
    pub use std::boxed::Box;
    pub use std::println;
    pub use std::string::String;
    pub use std::sync::Arc;
    pub use std::time::Duration;
    pub use std::vec::Vec;

    pub fn sleep(duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(not(feature = "std"))]
pub use m3types::*;

#[cfg(feature = "std")]
pub use stdtypes::*;
