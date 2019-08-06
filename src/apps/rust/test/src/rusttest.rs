/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

#[macro_use]
extern crate m3;

use m3::boxed::Box;
use m3::col::*;
use m3::com::*;
use m3::env;
use m3::io::*;
use m3::syscalls;
use m3::time;
use m3::vfs::*;
use m3::vpe::*;

#[no_mangle]
pub fn main() -> i32 {
    {
        let mut vpe = VPE::new_with(VPEArgs::new("test")).expect("Unable to create VPE");
        println!("VPE runs on {:?}", vpe.pe());

        vpe.mounts()
            .add("/", VPE::cur().mounts().get_by_path("/").unwrap())
            .unwrap();
        vpe.obtain_mounts().unwrap();

        let act = vpe.exec(&["/bin/ls", "-l", "/"]).expect("Exec failed");

        println!("foo: {}", act.vpe().sel());

        let res = act.wait().expect("Unable to wait for VPE");
        println!("VPE exited with {}", res);
    }

    {
        let mut vpe = VPE::new_with(VPEArgs::new("test")).expect("Unable to create VPE");
        println!("VPE runs on {:?}", vpe.pe());

        vpe.mounts()
            .add("/", VPE::cur().mounts().get_by_path("/").unwrap())
            .unwrap();
        vpe.obtain_mounts().unwrap();

        let file = VFS::open("/test.txt", OpenFlags::RW).expect("open of /test.txt failed");

        vpe.files()
            .set(0, VPE::cur().files().get(file.fd()).unwrap());
        vpe.obtain_fds().unwrap();

        let mut val = 42;
        let act = vpe
            .run(Box::new(move || {
                let f = VPE::cur().files().get(0).unwrap();
                let mut s = String::new();
                f.borrow_mut().read_to_string(&mut s).unwrap();
                println!("Read '{}'", s);

                println!("I'm a closure on PE {}", VPE::cur().pe_id());
                val += 1;
                println!("val = {}", val);
                val
            }))
            .expect("Unable to run VPE");

        let res = act.wait().expect("Unable to wait for VPE");
        println!("VPE exited with {}", res);
    }

    {
        for e in read_dir("/").expect("Unable to read directory") {
            println!("name: {}, inode: {}", e.file_name(), e.inode());
        }

        {
            let mut file = VFS::open("/test2.txt", OpenFlags::W | OpenFlags::CREATE)
                .expect("create of /test2.txt failed");

            writeln!(file, "This is the {:<2}th test of {:.3}", 42, 12.3).expect("write failed");
        }

        {
            let mut file =
                VFS::open("/test2.txt", OpenFlags::RW).expect("open of /test2.txt failed");

            let info = file.borrow().stat().unwrap();
            println!("Got info: {:?}", info);

            println!("File /test.txt: {:?}", VFS::stat("/test.txt").unwrap());
            println!(
                "Creating directory /foobar: {:?}",
                VFS::mkdir("/foobar", 0o755)
            );

            let mut s = String::new();
            {
                let count = file.read_to_string(&mut s).expect("read failed");
                println!("Got {} bytes: {}", count, s);
            }

            file.seek(0, SeekMode::SET).unwrap();
            {
                let count = file.read_to_string(&mut s).expect("read failed");
                println!("Got {} bytes: {}", count, s);
            }

            file.seek(0, SeekMode::END).unwrap();

            write!(file, "And this is another test!").expect("write failed");
        }

        {
            let mut file =
                VFS::open("/test2.txt", OpenFlags::RW).expect("open of /test2.txt failed");

            let mut s = String::new();
            let count = file.read_to_string(&mut s).expect("read failed");
            println!("Got {} bytes: {}", count, s);
        }
    }

    let vec = vec![1, 42, 23];
    println!("my vec:");
    for v in vec {
        println!("  {}", v);
    }

    let mut name = String::new();
    print!("Please enter your name: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut name).unwrap();
    println!("Thanks, {}!", name);

    let mut s: String = format!("my float is {:.3} and my args are", 12.5);
    for a in env::args() {
        s += " ";
        s += a;
    }
    println!("here: {}", s);

    for (i, a) in env::args().enumerate() {
        println!("arg {}: {}", i, a);
    }

    let args: Vec<&'static str> = env::args().collect();
    if args.len() > 2 {
        println!("arg0: {}, arg1: {}", args[0], args[1]);
    }

    {
        let mgate = MemGate::new(0x1000, Perm::RW).unwrap();
        let mgate2 = mgate.derive(0x100, 0x100, Perm::RW).unwrap();

        let mut data: [u8; 16] = [12; 16];
        mgate2.write(&data, 0).unwrap();
        mgate2.read(&mut data, 0).unwrap();
        println!("data: {:?}", data);

        MemGate::new(0x1000, Perm::RW).err();
    }

    {
        let mut rgate = RecvGate::new(12, 8).unwrap();
        rgate.activate().unwrap();

        let sgate = SendGate::new_with(SGateArgs::new(&rgate).credits((1 << 8) * 10).label(0x1234))
            .unwrap();

        let mut total = 0;
        for _ in 0..10 {
            let start = time::start(0xDEAD_BEEF);
            send_vmsg!(&sgate, RecvGate::def(), 23, 42, "foobar_test_asd").unwrap();

            let (a1, a2, a3) = recv_vmsg!(&rgate, i32, i32, String).unwrap();

            let end = time::stop(0xDEAD_BEEF);

            total += end - start;

            println!("msg: {} {} {}", a1, a2, a3);
        }

        println!("Time: {}", total / 10);
    }

    let mut total = 0;
    for _ in 0..10 {
        let start = time::start(0);
        syscalls::noop().unwrap();
        let end = time::stop(0);
        total += end - start;
    }
    assert!(total > 10);

    println!("per call: {}", total / 10);

    0
}
