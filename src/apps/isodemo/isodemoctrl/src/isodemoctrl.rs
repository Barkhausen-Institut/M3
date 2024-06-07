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

use m3::client::VTerm;
use m3::col::{String, ToString, Vec};
use m3::com::{RGateArgs, RecvGate, SGateArgs, SendGate};
use m3::errors::{Code, Error};
use m3::mem::MsgBuf;
use m3::rc::Rc;
use m3::serialize::M3Deserializer;
use m3::tcu::Message;
use m3::tiles::{ActivityArgs, ChildActivity, RunningActivity, RunningProgramActivity, Tile};
use m3::vfs::{BufReader, File, FileEvent, FileWaiter};
use m3::{format, send_recv};
use m3::{kif, syscalls};

use common::{ChildReply, ChildReq, Value};

const GAME: &str = "game";
const BOT_LEFT: &str = "bot-left";
const BOT_RIGHT: &str = "bot-right";

macro_rules! log {
    ($fmt:expr, $($arg:tt)*) => {
        m3::println!(concat!("!! ctrl: ", $fmt), $($arg)*)
    };
}

macro_rules! response {
    ($fmt:expr, $($arg:tt)*) => {
        m3::println!($fmt, $($arg)*)
    };
}

struct Child {
    name: String,
    act: RunningProgramActivity,
    _req_rgate: RecvGate,
    req_sgate: SendGate,
}

impl Drop for Child {
    fn drop(&mut self) {
        log!(
            "terminated activity {}:{}",
            self.act.activity().sel(),
            self.name
        );
    }
}

struct State {
    running: Vec<Child>,
    good_tile: Rc<Tile>,
    bad_tile: Rc<Tile>,
}

impl State {
    fn child_exists(&self, name: &str) -> bool {
        self.running.iter().find(|c| c.name == name).is_some()
    }

    fn get_req_sgate<'s>(&'s self, name: &str) -> Option<&'s SendGate> {
        self.running
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.req_sgate)
    }
}

#[derive(Debug)]
enum Command {
    StartGame,
    StopGame,
    StartBotLeft,
    StopBotLeft,
    StartBotRight,
    StopBotRight,

    GamePlay(Value),

    BotTrojan(Value),

    DemoStatus,

    Exit,
}

fn parse_cmd(line: &str) -> Result<Command, Error> {
    let mut words = line.split(',');
    let first = words.next().ok_or_else(|| Error::new(Code::InvArgs))?;
    let mut parse_int = || -> Result<Value, Error> {
        words
            .next()
            .ok_or_else(|| Error::new(Code::InvArgs))?
            .parse()
            .map_err(|_| Error::new(Code::InvArgs))
    };

    let cmd = match first {
        "start_game" => Command::StartGame,
        "stop_game" => Command::StopGame,
        "start_botLeft" => Command::StartBotLeft,
        "stop_botLeft" => Command::StopBotLeft,
        "start_botRight" => Command::StartBotRight,
        "stop_botRight" => Command::StopBotRight,

        "game_play" => Command::GamePlay(parse_int()?),
        "human_play" => Command::GamePlay(parse_int()? * 10 + 1),
        "bot_play" => Command::GamePlay(parse_int()? * 10 + 3),

        "bot_trojan" => Command::BotTrojan(parse_int()? * 10 + 3),

        "demo_status" => Command::DemoStatus,

        "exit" => Command::Exit,

        _ => return Err(Error::new(Code::InvArgs)),
    };
    Ok(cmd)
}

fn cmd_start(state: &State, name: &str, tile: Rc<Tile>) -> Result<Child, Error> {
    if state.running.iter().find(|c| c.name == name).is_some() {
        return Err(Error::new(Code::Exists));
    }

    let act = ChildActivity::new_with(tile.clone(), ActivityArgs::new(name))?;

    let req_rgate = RecvGate::new_with(RGateArgs::default().order(8).msg_order(8))?;
    act.delegate_obj(req_rgate.sel())?;
    let req_sgate = SendGate::new_with(SGateArgs::new(&req_rgate).credits(1))?;

    let req_sel_str = format!("{}", req_rgate.sel());
    let args = match name {
        BOT_LEFT | BOT_RIGHT => ["/bin/isodemoattacker", &req_sel_str],
        GAME => ["/bin/isodemovictim", &req_sel_str],
        &_ => return Err(Error::new(Code::NotFound)),
    };
    log!(
        "starting {}:{} with {:?} on {}",
        act.sel(),
        name,
        args,
        tile.id()
    );
    act.exec(&args).map(|run| Child {
        name: name.to_string(),
        act: run,
        _req_rgate: req_rgate,
        req_sgate,
    })
}

fn cmd_stop(state: &mut State, name: &str) {
    state.running.retain(|c| name != c.name);
}

fn child_request(state: &State, name: &str, req: ChildReq) -> Value {
    match perform_request(state, name, &req) {
        Ok(val) => val,
        Err(e) => {
            log!("request {:?} to {} failed: {:?}", req, name, e);
            0
        },
    }
}

fn perform_request(state: &State, name: &str, req: &ChildReq) -> Result<Value, Error> {
    match state.get_req_sgate(name) {
        Some(sg) => {
            let mut reply = send_recv!(sg, RecvGate::def(), req)?;
            let reply: ChildReply = reply.pop()?;
            if reply.res != Code::Success {
                Err(Error::new(reply.res))
            }
            else {
                Ok(reply.val)
            }
        },
        None => Err(Error::new(Code::NotFound)),
    }
}

fn handle_command(state: &mut State, line: &str, cmd: Result<Command, Error>) -> bool {
    match cmd {
        // start/stop game
        Ok(Command::StartGame) => match cmd_start(state, GAME, state.bad_tile.clone()) {
            Ok(child) => state.running.push(child),
            Err(e) => log!("unable to start victim: {}", e),
        },
        Ok(Command::StopGame) => cmd_stop(state, GAME),

        // start/stop bot left
        Ok(Command::StartBotLeft) => {
            match cmd_start(state, BOT_LEFT, state.bad_tile.clone()) {
                Ok(child) => state.running.push(child),
                Err(e) => log!("unable to start victim: {}", e),
            }
        },
        Ok(Command::StopBotLeft) => cmd_stop(state, BOT_LEFT),

        // start/stop bot right
        Ok(Command::StartBotRight) => {
            match cmd_start(state, BOT_RIGHT, state.good_tile.clone()) {
                Ok(child) => state.running.push(child),
                Err(e) => log!("unable to start victim: {}", e),
            }
        },
        Ok(Command::StopBotRight) => cmd_stop(state, BOT_RIGHT),

        // child requests
        Ok(Command::GamePlay(val)) => {
            if val == 1000 {
                child_request(state, GAME, ChildReq::Play(1000));
            } else if val == 1001 {
                child_request(state, GAME, ChildReq::Play(1001));
            } else if (val % 10) == 1 {
                log!("human is playing{}", "");
                child_request(state, GAME, ChildReq::Play(val));
            } else {
                if state.child_exists(BOT_LEFT) {
                    log!("botLeft is playing{}", "");
                    child_request(state, GAME, ChildReq::Play(val / 10 * 10 + 2));
                }
                if state.child_exists(BOT_RIGHT) {
                    log!("botRight is playing{}", "");
                    child_request(state, GAME, ChildReq::Play(val / 10 * 10 + 3));
                }
                if (!state.child_exists(BOT_LEFT)) & (!state.child_exists(BOT_RIGHT)) {
                    log!("cannot play without running bot{}", "");
                }
            }
        },
        Ok(Command::BotTrojan(val)) => {
            if state.child_exists(BOT_LEFT) {
                child_request(state, BOT_LEFT, ChildReq::Trojan(val / 10 * 10 + 2));
            }
            if state.child_exists(BOT_RIGHT) {
                child_request(state, BOT_RIGHT, ChildReq::Trojan(val / 10 * 10 + 3));
            }
            if (!state.child_exists(BOT_LEFT)) & (!state.child_exists(BOT_RIGHT)) {
                log!("cannot trojan without running bot{}", "");
            }
        },

        Ok(Command::DemoStatus) => {
            let game_running = state.child_exists(GAME);
            let bot_left_running = state.child_exists(BOT_LEFT);
            let bot_right_running = state.child_exists(BOT_RIGHT);
            let mut game_log_length = 0;
            let mut game_board = 0;
            let mut game_log_0 = 0;
            let mut game_log_1 = 0;
            let mut game_log_2 = 0;
            let mut game_log_3 = 0;
            let mut game_log_4 = 0;
            let mut game_log_5 = 0;
            let mut game_log_6 = 0;
            let mut game_log_7 = 0;
            let mut game_log_8 = 0;
            if state.child_exists(GAME) {
                game_board = child_request(state, GAME, ChildReq::GetBoard);
                game_log_0 = child_request(state, GAME, ChildReq::GetLog(0));
                if game_log_0 > 0 {game_log_length = 1;}
                game_log_1 = child_request(state, GAME, ChildReq::GetLog(1));
                if game_log_1 > 0 {game_log_length = 2;}
                game_log_2 = child_request(state, GAME, ChildReq::GetLog(2));
                if game_log_2 > 0 {game_log_length = 3;}
                game_log_3 = child_request(state, GAME, ChildReq::GetLog(3));
                if game_log_3 > 0 {game_log_length = 4;}
                game_log_4 = child_request(state, GAME, ChildReq::GetLog(4));
                if game_log_4 > 0 {game_log_length = 5;}
                game_log_5 = child_request(state, GAME, ChildReq::GetLog(5));
                if game_log_5 > 0 {game_log_length = 6;}
                game_log_6 = child_request(state, GAME, ChildReq::GetLog(6));
                if game_log_6 > 0 {game_log_length = 7;}
                game_log_7 = child_request(state, GAME, ChildReq::GetLog(7));
                if game_log_7 > 0 {game_log_length = 8;}
                game_log_8 = child_request(state, GAME, ChildReq::GetLog(8));
                if game_log_8 > 0 {game_log_length = 9;}
            }
            let mut next_player = "human";
            if game_log_length % 2 == 1 {
                next_player = "bot";
            }
            response!(
                concat!(
                    "status: {{ ",
                    "\"gameBoard\": {}, ",
                    "\"gameRunning\": {}, ",
                    "\"botLeftRunning\": {}, ",
                    "\"botRightRunning\": {}, ",
                    "\"nextPlayer\": \"{}\", ",
                    "\"gameLog\": [{}, {}, {}, {}, {}, {}, {}, {}, {}]",
                    "}}"
                ),
                game_board,
                game_running,
                bot_left_running,
                bot_right_running,
                next_player,
                game_log_0,
                game_log_1,
                game_log_2,
                game_log_3,
                game_log_4,
                game_log_5,
                game_log_6,
                game_log_7,
                game_log_8,
            );
        },

        Ok(Command::Exit) => return false,

        Err(e) => log!("unable to parse command '{}': {}", line, e),
    }
    true
}

fn start_upcall(state: &mut State) {
    let sels = state
        .running
        .iter()
        .map(|c| c.act.activity().sel())
        .collect::<Vec<_>>();
    syscalls::activity_wait(&sels, 1).expect("activity_wait failed");
}

fn handle_upcall(msg: &'static Message, state: &mut State) {
    let mut de = M3Deserializer::new(msg.as_words());
    let opcode: kif::upcalls::Operation = de.pop().unwrap();
    assert_eq!(opcode, kif::upcalls::Operation::ActWait);
    let upcall: kif::upcalls::ActivityWait = de.pop().unwrap();

    log!(
        "activity {} exited with exit code {:?}",
        upcall.act_sel,
        upcall.exitcode
    );
    state
        .running
        .retain(|c| c.act.activity().sel() != upcall.act_sel);

    let mut reply_buf = MsgBuf::borrow_def();
    m3::build_vmsg!(reply_buf, kif::DefaultReply {
        error: Code::Success
    });
    RecvGate::upcall()
        .reply(&reply_buf, msg)
        .expect("Upcall reply failed");
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let vterm = VTerm::new("vterm").expect("Unable to open session at 'vterm'");

    let mut reader = BufReader::new(
        vterm
            .create_channel(true)
            .expect("Unable to open read channel"),
    );

    reader
        .get_mut()
        .set_blocking(false)
        .expect("Unable to set channel to non-blocking");

    let mut state = State {
        running: Vec::new(),
        good_tile: Tile::get("rocket|core").expect("Unable to get good tile"),
        bad_tile: Tile::get("boom+nic|core").expect("Unable to get bad tile"),
    };

    log!("found good tile: {}", state.good_tile.id());
    log!("found bad tile: {}", state.bad_tile.id());

    let mut waiter = FileWaiter::default();
    waiter.add(reader.get_ref().fd(), FileEvent::INPUT);

    let mut line = String::new();
    loop {
        if reader.read_line(&mut line).is_ok() {
            if line.is_empty() {
                continue;
            }

            let cmd = parse_cmd(&line);
            if !handle_command(&mut state, &line, cmd) {
                break;
            }

            start_upcall(&mut state);

            line.clear();
        }

        if let Ok(msg) = RecvGate::upcall().fetch() {
            handle_upcall(msg, &mut state);
            start_upcall(&mut state);
        }

        waiter.wait_cond(|| RecvGate::upcall().has_msgs().unwrap());
    }

    Ok(())
}
