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

use core::str::FromStr;

use m3::client::VTerm;
use m3::col::{String, ToString, Vec};
use m3::com::{GateIStream, RGateArgs, RecvGate, SGateArgs, SendGate};
use m3::errors::{Code, Error};
use m3::mem::MsgBuf;
use m3::rc::Rc;
use m3::serialize::M3Deserializer;
use m3::tcu::Message;
use m3::tiles::{ActivityArgs, ChildActivity, RunningActivity, RunningProgramActivity, Tile};
use m3::vfs::{BufReader, File, FileEvent, FileWaiter};
use m3::{format, reply_vmsg};
use m3::{kif, syscalls};

macro_rules! ctrl_print {
    ($fmt:expr, $($arg:tt)*) => {
        m3::println!(concat!("!! ctrl: ", $fmt), $($arg)*)
    };
}

struct Child {
    name: String,
    act: RunningProgramActivity,
    _sgate: SendGate,
}

impl Drop for Child {
    fn drop(&mut self) {
        ctrl_print!(
            "terminated activity {}:{}",
            self.act.activity().sel(),
            self.name
        );
    }
}

#[derive(PartialEq)]
enum TileType {
    Good,
    Bad,
}

impl FromStr for TileType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "good" => Ok(Self::Good),
            "bad" => Ok(Self::Bad),
            _ => Err(Error::new(Code::InvArgs)),
        }
    }
}

enum Command {
    Start(String, String, TileType),
    Stop(String),
    List,
    Exit,
}

fn parse_cmd(line: &str) -> Result<Command, Error> {
    let mut words = line.split(' ');
    let first = words.next().ok_or_else(|| Error::new(Code::InvArgs))?;
    let cmd = match first {
        "start" => Command::Start(
            words
                .next()
                .ok_or_else(|| Error::new(Code::InvArgs))?
                .to_string(),
            words
                .next()
                .ok_or_else(|| Error::new(Code::InvArgs))?
                .to_string(),
            TileType::from_str(words.next().unwrap_or("bad"))?,
        ),
        "stop" => Command::Stop(
            words
                .next()
                .ok_or_else(|| Error::new(Code::InvArgs))?
                .to_string(),
        ),
        "list" => Command::List,
        "exit" => Command::Exit,
        _ => return Err(Error::new(Code::InvArgs)),
    };
    Ok(cmd)
}

fn cmd_start(name: &str, arg: &str, rgate: &RecvGate, tile: Rc<Tile>) -> Result<Child, Error> {
    let act = ChildActivity::new_with(tile.clone(), ActivityArgs::new(name))?;

    let sgate = SendGate::new_with(SGateArgs::new(rgate).credits(1))?;
    act.delegate_obj(sgate.sel())?;

    let sel_str = format!("{}", sgate.sel());
    let args = match name {
        "attacker" => ["/bin/isodemoattacker", arg, &sel_str],
        "victim" => ["/bin/isodemovictim", arg, &sel_str],
        &_ => return Err(Error::new(Code::NotFound)),
    };
    ctrl_print!(
        "starting {}:{} with {:?} on {}",
        act.sel(),
        name,
        args,
        tile.id()
    );
    act.exec(&args).map(|run| Child {
        name: name.to_string(),
        act: run,
        _sgate: sgate,
    })
}

fn cmd_stop(name: &str, running: &mut Vec<Child>) {
    running.retain(|c| name != c.name);
}

fn cmd_list(running: &Vec<Child>) {
    for c in running {
        ctrl_print!(
            "{}:{} on tile {}",
            c.act.activity().sel(),
            c.name,
            c.act.activity().tile().id()
        );
    }
}

fn start_upcall(running: &mut Vec<Child>) {
    let sels = running
        .iter()
        .map(|c| c.act.activity().sel())
        .collect::<Vec<_>>();
    syscalls::activity_wait(&sels, 1).expect("activity_wait failed");
}

fn handle_upcall(msg: &'static Message, running: &mut Vec<Child>) {
    let mut de = M3Deserializer::new(msg.as_words());
    let opcode: kif::upcalls::Operation = de.pop().unwrap();
    assert_eq!(opcode, kif::upcalls::Operation::ActWait);
    let upcall: kif::upcalls::ActivityWait = de.pop().unwrap();

    ctrl_print!(
        "activity {} exited with exit code {:?}",
        upcall.act_sel,
        upcall.exitcode
    );
    running.retain(|c| c.act.activity().sel() != upcall.act_sel);

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

    let mut running = Vec::new();
    let good_tile = Tile::get("rocket|core").expect("Unable to get good tile");
    let bad_tile = Tile::get("boom+nic|core").expect("Unable to get bad tile");
    ctrl_print!("found good tile: {}", good_tile.id());
    ctrl_print!("found bad tile: {}", bad_tile.id());

    let mut waiter = FileWaiter::default();
    waiter.add(reader.get_ref().fd(), FileEvent::INPUT);

    let rgate = RecvGate::new_with(RGateArgs::default().order(14).msg_order(9))
        .expect("Unable to create receive gate");

    let mut line = String::new();
    loop {
        if reader.read_line(&mut line).is_ok() {
            if line.is_empty() {
                continue;
            }

            let cmd = parse_cmd(&line);
            match cmd {
                Ok(Command::Start(name, arg, tile_type)) => {
                    let selected_tile = match tile_type {
                        TileType::Good => good_tile.clone(),
                        TileType::Bad => bad_tile.clone(),
                    };
                    match cmd_start(&name, &arg, &rgate, selected_tile) {
                        Ok(child) => running.push(child),
                        Err(e) => ctrl_print!("unable to start start {}: {}", name, e),
                    }
                },
                Ok(Command::Stop(name)) => cmd_stop(&name, &mut running),
                Ok(Command::List) => cmd_list(&running),
                Ok(Command::Exit) => break,
                Err(e) => ctrl_print!("unable to parse command '{}': {}", line, e),
            }

            start_upcall(&mut running);

            line.clear();
        }

        if let Ok(msg) = rgate.fetch() {
            let mut is = GateIStream::new(msg, &rgate);
            let msg: &str = is.pop().unwrap();
            m3::println!("{}", msg);
            reply_vmsg!(is, 0).unwrap();
        }

        if let Ok(msg) = RecvGate::upcall().fetch() {
            handle_upcall(msg, &mut running);
            start_upcall(&mut running);
        }

        waiter.wait_cond(|| rgate.has_msgs().unwrap() || RecvGate::upcall().has_msgs().unwrap());
    }

    Ok(())
}
