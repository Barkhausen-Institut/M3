/*
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
 *
 * This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
 *
 * M3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * M3 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 */

use core::arch::asm;

use crate::arch::TMABIOps;
use crate::errors::Error;
use crate::tmif::Operation;

pub struct RISCVTMABI {}

impl TMABIOps for RISCVTMABI {
    fn call1(op: Operation, arg1: usize) -> Result<(), Error> {
        Self::call2(op, arg1, 0)
    }

    fn call2(op: Operation, arg1: usize, arg2: usize) -> Result<(), Error> {
        let mut res = op.into();
        unsafe {
            asm!(
                "ecall",
                inout("x10") res,
                in("x11") arg1,
                in("x12") arg2,
            );
        }
        crate::tmif::get_result(res)
    }

    fn call3(op: Operation, arg1: usize, arg2: usize, arg3: usize) -> Result<(), Error> {
        let mut res = op.into();
        unsafe {
            asm!(
                "ecall",
                inout("x10") res,
                in("x11") arg1,
                in("x12") arg2,
                in("x13") arg3,
            );
        }
        crate::tmif::get_result(res)
    }

    fn call4(
        op: Operation,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
    ) -> Result<(), Error> {
        let mut res = op.into();
        unsafe {
            asm!(
                "ecall",
                inout("x10") res,
                in("x11") arg1,
                in("x12") arg2,
                in("x13") arg3,
                in("x14") arg4,
            );
        }
        crate::tmif::get_result(res)
    }
}
