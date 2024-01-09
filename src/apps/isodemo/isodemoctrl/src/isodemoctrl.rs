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

const SENSOR: &str = "sensor";
const DISPLAY_LEFT: &str = "display-left";
const DISPLAY_RIGHT: &str = "display-right";

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

#[derive(Default)]
struct Logger {
    vals: [Value; 8],
    idx: usize,
}

struct State {
    running: Vec<Child>,
    logger: Option<Logger>,
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
    StartSensor,
    StopSensor,
    StartLogger,
    StopLogger,
    StartDisplayLeft,
    StopDisplayLeft,
    StartDisplayRight,
    StopDisplayRight,

    SensorStore(Value),
    LoggerLog,

    DisplayLeftDisplay,
    DisplayRightDisplay,

    DisplayLeftTrojan(Value),
    DisplayRightTrojan(Value),

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
        "start_sensor" => Command::StartSensor,
        "stop_sensor" => Command::StopSensor,
        "start_logger" => Command::StartLogger,
        "stop_logger" => Command::StopLogger,
        "start_displayLeft" => Command::StartDisplayLeft,
        "stop_displayLeft" => Command::StopDisplayLeft,
        "start_displayRight" => Command::StartDisplayRight,
        "stop_displayRight" => Command::StopDisplayRight,

        "sensor_store" => Command::SensorStore(parse_int()?),
        "logger_log" => Command::LoggerLog,

        "displayLeft_display" => Command::DisplayLeftDisplay,
        "displayRight_display" => Command::DisplayRightDisplay,

        "displayLeft_trojan" => Command::DisplayLeftTrojan(parse_int()?),
        "displayRight_trojan" => Command::DisplayRightTrojan(parse_int()?),

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
        DISPLAY_LEFT | DISPLAY_RIGHT => ["/bin/isodemoattacker", &req_sel_str],
        SENSOR => ["/bin/isodemovictim", &req_sel_str],
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

fn weather(val: Value) -> &'static str {
    match val {
        -128..=0 => "icy",
        1..=5 => "foggy",
        6..=15 => "rainy",
        16..=25 => "cloudy",
        26..=40 => "sunny",
        _ => "hellfire",
    }
}

fn handle_command(state: &mut State, line: &str, cmd: Result<Command, Error>) -> bool {
    match cmd {
        // start/stop sensor
        Ok(Command::StartSensor) => match cmd_start(state, SENSOR, state.bad_tile.clone()) {
            Ok(child) => state.running.push(child),
            Err(e) => log!("unable to start victim: {}", e),
        },
        Ok(Command::StopSensor) => cmd_stop(state, SENSOR),

        // start/stop display left
        Ok(Command::StartDisplayLeft) => {
            match cmd_start(state, DISPLAY_LEFT, state.bad_tile.clone()) {
                Ok(child) => state.running.push(child),
                Err(e) => log!("unable to start victim: {}", e),
            }
        },
        Ok(Command::StopDisplayLeft) => cmd_stop(state, DISPLAY_LEFT),

        // start/stop display left
        Ok(Command::StartDisplayRight) => {
            match cmd_start(state, DISPLAY_RIGHT, state.good_tile.clone()) {
                Ok(child) => state.running.push(child),
                Err(e) => log!("unable to start victim: {}", e),
            }
        },
        Ok(Command::StopDisplayRight) => cmd_stop(state, DISPLAY_RIGHT),

        // child requests
        Ok(Command::SensorStore(val)) => {
            child_request(state, SENSOR, ChildReq::Set(val));
        },
        Ok(Command::DisplayLeftDisplay) => {
            let val = if state.child_exists(DISPLAY_LEFT) {
                child_request(state, SENSOR, ChildReq::Get)
            }
            else {
                0
            };
            response!("displayLeft: {{ \"display\": \"{}\" }}", weather(val));
        },
        Ok(Command::DisplayRightDisplay) => {
            let val = if state.child_exists(DISPLAY_RIGHT) {
                child_request(state, SENSOR, ChildReq::Get)
            }
            else {
                0
            };
            response!("displayRight: {{ \"display\": \"{}\" }}", weather(val));
        },
        Ok(Command::DisplayLeftTrojan(val)) => {
            child_request(state, DISPLAY_LEFT, ChildReq::Attack(val));
        },
        Ok(Command::DisplayRightTrojan(val)) => {
            child_request(state, DISPLAY_RIGHT, ChildReq::Attack(val));
        },

        // start/stop logger
        Ok(Command::StartLogger) => {
            if state.logger.is_some() {
                log!("unable to start logger: {}", Error::new(Code::Exists));
            }
            else {
                state.logger = Some(Logger::default());
            }
        },
        Ok(Command::StopLogger) => {
            state.logger = None;
        },

        Ok(Command::LoggerLog) => {
            let val = child_request(state, SENSOR, ChildReq::Get);
            if let Some(ref mut log) = state.logger.as_mut() {
                log.vals[log.idx] = val;
                log.idx = (log.idx + 1) % log.vals.len();
            }
        },

        Ok(Command::DemoStatus) => {
            let sensor_value = child_request(state, SENSOR, ChildReq::Get);
            let sensor_running = state.child_exists(SENSOR);
            let display_left_running = state.child_exists(DISPLAY_LEFT);
            let display_right_running = state.child_exists(DISPLAY_RIGHT);
            let logger_running = state.logger.is_some();
            let logger_values = match state.logger.as_ref() {
                Some(log) => log.vals,
                None => [0; 8],
            };
            response!(
                concat!(
                    "status: {{ ",
                    "\"sensorValue\": {}, \"loggerValues\": {:?}, ",
                    "\"sensorRunning\": {}, \"loggerRunning\": {}, ",
                    "\"displayLeftRunning\": {}, \"displayRightRunning\": {} ",
                    "}}"
                ),
                sensor_value,
                logger_values,
                sensor_running,
                logger_running,
                display_left_running,
                display_right_running,
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
        logger: None,
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
