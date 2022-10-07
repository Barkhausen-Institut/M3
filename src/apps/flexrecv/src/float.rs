#[cfg(not(feature = "std"))]
pub const SQRT_2: f32 = 1.41421356237309504880168872420969808f32; // 1.41421354f32
#[cfg(feature = "std")]
use std::f32::consts::SQRT_2;

#[cfg(not(feature = "std"))]
pub trait FloatOps {
    fn sqrt(self) -> f32;
    fn round(self) -> f32;
    fn abs(self) -> f32;
    fn powi(self, n: i32) -> f32;
    fn ln(self) -> f32;
    fn exp(self) -> f32;
}

#[cfg(not(feature = "std"))]
impl FloatOps for f32 {
    fn sqrt(self) -> f32 {
        unsafe { core::intrinsics::sqrtf32(self) }
    }

    fn round(self) -> f32 {
        unsafe { core::intrinsics::roundf32(self) }
    }

    fn abs(self) -> f32 {
        unsafe { core::intrinsics::fabsf32(self) }
    }

    fn powi(self, n: i32) -> f32 {
        unsafe { core::intrinsics::powif32(self, n) }
    }

    fn ln(self) -> f32 {
        unsafe { core::intrinsics::logf32(self) }
    }

    fn exp(self) -> f32 {
        unsafe { core::intrinsics::expf32(self) }
    }
}
