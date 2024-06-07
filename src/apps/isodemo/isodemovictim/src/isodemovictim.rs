/*
 * Copyright (C) 2023 Nils Asmussen, Barkhausen Institut
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

#[path = "../../common.rs"]
mod common;

use m3::cap::Selector;
use m3::client::MapFlags;
use m3::com::{recv_msg, RecvGate};
use m3::env;
use m3::errors::{Code, Error};
use m3::kif::Perm;
use m3::mem::{PhysAddr, VirtAddr};
use m3::tiles::Activity;
use m3::vec::Vec;
use m3::{cfg, reply_vmsg};

use common::{ChildReply, ChildReq, Value};

macro_rules! log {
    ($fmt:expr, $($arg:tt)*) => {
        m3::println!(concat!("!! victim: ", $fmt), $($arg)*)
    };
}

macro_rules! response {
    ($fmt:expr, $($arg:tt)*) => {
        m3::println!($fmt, $($arg)*)
    };
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let args = env::args().collect::<Vec<_>>();

    let req_sel: Selector = args[1].parse().expect("Unable to parse request selector");

    let req_rgate = RecvGate::new_bind(req_sel);

    let virt = VirtAddr::from(0x3000_0000);
    Activity::own()
        .pager()
        .unwrap()
        .map_anon(virt, cfg::PAGE_SIZE, Perm::RW, MapFlags::PRIVATE)
        .expect("Unable to map anon memory");

    // map UART
    m3::tmif::map(
        VirtAddr::new(0x0400_0000),
        PhysAddr::new_raw(0x0400_0000),
        1,
        m3::kif::Perm::RW,
    )
    .unwrap();

    let val = [0; 9];
    unsafe {
        core::ptr::copy_nonoverlapping(val.as_ptr(), virt.as_mut_ptr(), val.len());
    }
    let game_log: &mut [Value] =
        unsafe { core::slice::from_raw_parts_mut(virt.as_mut_ptr(), val.len()) };

    let mut last_player: Value = -1;

    fn get_field_owner(field: Value, board: Value) -> Value {
        (((board >> (2 * field)) & 0x03) + 2) % 4 - 2
    }

    fn get_row_col_owner(row: Value, col: Value, board: Value) -> Value {
        get_field_owner(col + 3 * row, board)
    }

    while let Ok(mut msg) = recv_msg(&req_rgate) {
        let cmd: ChildReq = msg.pop().unwrap();
        let reply = match cmd {
            ChildReq::GetBoard => ChildReply::new_with_val(Code::Success, game_log[0]),
            ChildReq::GetLog(val) => {
                ChildReply::new_with_val(Code::Success, game_log[val as usize])
            },
            ChildReq::Play(val) => {
                const UART_BASE: *mut u32 = 0x0400_0000 as *mut u32;
                const UART_TXDATA: *mut u32 = 0x0400_0000 as *mut u32;
                const UART_RXDATA: *mut u32 = 0x0400_0004 as *mut u32;
                const UART_TXCTRL: *mut u32 = 0x0400_0008 as *mut u32;
                const UART_RXCTRL: *mut u32 = 0x0400_000C as *mut u32;
                const UART_IE: *mut u32 = 0x0400_0010 as *mut u32;
                const UART_IP: *mut u32 = 0x0400_0014 as *mut u32;
                const UART_DIV: *mut u32 = 0x0400_0018 as *mut u32;

                unsafe {
                    UART_TXCTRL.write_volatile(1);
                    UART_RXCTRL.write_volatile(1);
                    UART_DIV.write_volatile(694);

                    UART_TXDATA.write_volatile(85);
                }
                log!("serial_test: {:?}", 85);

                // 0b .. .. .. .. .. .. .. 22 21 20 12 11 10 02 01 00
                // with 00..22: 0-none, 1-blue, 2-green, 3-red

                let row = val / 100 % 10;
                let col = val / 10 % 10;
                let mut player = val % 10;
                let mut step_player = "human";
                let mut step_success = false;
                if player == 2 {
                    step_player = "botLeft";
                    player = -1;
                }
                if player == 3 {
                    step_player = "botRight";
                    player = -1;
                }
                log!("play player: {}", player);
                log!("play row: {}", row);
                log!("play col: {}", col);

                // // check if its players turn
                if player == last_player {
                    player = 0;
                    log!("move rejected: other players turn{}", "");
                }
                // let mut bias = 0;
                // for field in 0..9 {
                //     if get_field_owner(field, game_log[0]) == 1 {
                //         bias = bias + 1;
                //     }
                //     if get_field_owner(field,game_log[0]) == -1 {
                //         bias = bias - 1;
                //     }
                // }
                //if (player == 1) & (bias > 0) {
                //    player = 0;
                //    log!("move rejected: it's not humans turn{}", "");
                // }
                // if (player == -1) & (bias <= 0) {
                //     player = 0;
                //     log!("move rejected: it's not bots turn{}", "");
                // }

                // check if field already played
                if get_row_col_owner(row, col, game_log[0]) != 0 {
                    player = 0;
                    log!("move rejected: field already owned{}", "");
                }

                // check if game already ended
                for straight in 0..3 {
                    let row_sum = get_row_col_owner(straight, 0, game_log[0])
                        + get_row_col_owner(straight, 1, game_log[0])
                        + get_row_col_owner(straight, 2, game_log[0]);
                    let col_sum = get_row_col_owner(0, straight, game_log[0])
                        + get_row_col_owner(1, straight, game_log[0])
                        + get_row_col_owner(2, straight, game_log[0]);
                    if (row_sum == 3) | (col_sum == 3) {
                        player = 0;
                        log!("move rejected: game already won by human{}", "");
                    }
                    if (row_sum == -3) | (col_sum == -3) {
                        player = 0;
                        log!("move rejected: game already won by bot{}", "");
                    }
                }
                let diag_sum_down = get_row_col_owner(0, 0, game_log[0])
                    + get_row_col_owner(1, 1, game_log[0])
                    + get_row_col_owner(2, 2, game_log[0]);

                let diag_sum_up = get_row_col_owner(0, 2, game_log[0])
                    + get_row_col_owner(1, 1, game_log[0])
                    + get_row_col_owner(2, 0, game_log[0]);
                if (diag_sum_down == 3) | (diag_sum_up == 3) {
                    log!("move rejected: game already won by human{}", "");
                }
                if (diag_sum_down == -3) | (diag_sum_up == -3) {
                    log!("move rejected: game already won by bot{}", "");
                }

                // play the move if valid
                if player != 0 {
                    step_success = true;
                    let mut player_value = 0x1;
                    last_player = 1;
                    if player == -1 {
                        player_value = 0x3;
                        last_player = -1
                    }
                    game_log[8] = game_log[7];
                    game_log[7] = game_log[6];
                    game_log[6] = game_log[5];
                    game_log[5] = game_log[4];
                    game_log[4] = game_log[3];
                    game_log[3] = game_log[2];
                    game_log[2] = game_log[1];
                    game_log[1] = game_log[0];
                    game_log[0] = game_log[0] | (player_value << (2 * (col + 3 * row)));
                }

                response!(
                    concat!(
                        "step: {{ ",
                        "\"player\": \"{}\", ",
                        "\"success\": {}, ",
                        "\"cheat\": {}",
                        "}}"
                    ),
                    step_player,
                    step_success,
                    false
                );

                ChildReply::new(Code::Success)
            },
            _ => {
                log!("unsupported command: {:?}", cmd);
                ChildReply::new(Code::InvArgs)
            },
        };

        reply_vmsg!(msg, reply).unwrap();
    }

    Ok(())
}
