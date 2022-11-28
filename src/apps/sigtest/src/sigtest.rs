/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

#![no_std]

use m3::errors::Error;
use m3::println;
use m3::tiles::Activity;

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let quote = Activity::own()
        .resmng()
        .unwrap()
        .quote()
        .expect("quote failed");
    println!("quote = {}", quote);
    Ok(())
}
