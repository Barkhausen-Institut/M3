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

use m3::client::VTerm;
use m3::col::{String, ToString, Vec};
use m3::com::RecvGate;
use m3::errors::{Code, Error};
use m3::mem::MsgBuf;
use m3::println;
use m3::rc::Rc;
use m3::serialize::M3Deserializer;
use m3::tcu::Message;
use m3::tiles::{ActivityArgs, ChildActivity, RunningActivity, RunningProgramActivity, Tile};
use m3::vfs::{BufReader, File, FileEvent, FileWaiter};
use m3::{kif, syscalls};

struct Child {
    name: String,
    act: RunningProgramActivity,
}

impl Drop for Child {
    fn drop(&mut self) {
        println!(
            "Terminated activity {}:{}",
            self.act.activity().sel(),
            self.name
        );
    }
}

enum Command {
    Start(String, String),
    Stop(String),
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
        ),
        "stop" => Command::Stop(
            words
                .next()
                .ok_or_else(|| Error::new(Code::InvArgs))?
                .to_string(),
        ),
        _ => return Err(Error::new(Code::InvArgs)),
    };
    Ok(cmd)
}

fn cmd_start(name: &str, arg: &str, tile: Rc<Tile>) -> Result<RunningProgramActivity, Error> {
    let act = ChildActivity::new_with(tile, ActivityArgs::new(name))?;

    let args = match name {
        "attacker" => ["/bin/isodemoattacker", arg],
        "victim" => ["/bin/isodemovictim", arg],
        &_ => return Err(Error::new(Code::NotFound)),
    };
    println!("Starting {}:{} with {:?}", act.sel(), name, args);
    act.exec(&args)
}

fn cmd_stop(name: &str, running: &mut Vec<Child>) {
    running.retain(|c| name != c.name);
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

    println!(
        "Activity {} exited with exit code {:?}",
        upcall.act_sel, upcall.exitcode
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
    let shared_tile = Tile::get("boom+nic|core").expect("Unable to get shared tile");

    let mut waiter = FileWaiter::default();
    waiter.add(reader.get_ref().fd(), FileEvent::INPUT);

    let mut line = String::new();
    loop {
        if reader.read_line(&mut line).is_ok() {
            if line.is_empty() {
                break;
            }

            let cmd = parse_cmd(&line);
            match cmd {
                Ok(Command::Start(name, arg)) => {
                    match cmd_start(&name, &arg, shared_tile.clone()) {
                        Ok(act) => running.push(Child { name, act }),
                        Err(e) => println!("Unable to start start {}: {}", name, e),
                    }
                },
                Ok(Command::Stop(name)) => cmd_stop(&name, &mut running),
                Err(e) => println!("Unable to parse command '{}': {}", line, e),
            }

            start_upcall(&mut running);

            line.clear();
        }

        if let Ok(msg) = RecvGate::upcall().fetch() {
            handle_upcall(msg, &mut running);
            start_upcall(&mut running);
        }

        waiter.wait_cond(|| RecvGate::upcall().has_msgs().unwrap());
    }

    Ok(())
}
