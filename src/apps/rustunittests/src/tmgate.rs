/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
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

use core::ptr::addr_of;

use m3::cap::Selector;
use m3::cfg;
use m3::client::MapFlags;
use m3::com::{MGateArgs, MemGate, Perm, Semaphore};
use m3::errors::Code;
use m3::mem::{GlobOff, VirtAddr};
use m3::test::WvTester;
use m3::tiles::{Activity, ChildActivity, RunningActivity, Tile};
use m3::util::math;
use m3::{wv_assert_eq, wv_assert_err, wv_assert_ok, wv_run_test};

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, create);
    wv_run_test!(t, create_readonly);
    wv_run_test!(t, create_writeonly);
    wv_run_test!(t, derive);
    wv_run_test!(t, read_write);
    wv_run_test!(t, read_write_object);
    wv_run_test!(t, remote_access);
}

fn create(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        MemGate::new_with(MGateArgs::new(0x1000, Perm::R).sel(1)),
        Code::InvArgs
    );
}

fn create_readonly(t: &mut dyn WvTester) {
    let mgate = wv_assert_ok!(MemGate::new(0x1000, Perm::R));
    let mut data = [0u8; 8];
    wv_assert_err!(t, mgate.write(&data, 0), Code::NoPerm);
    wv_assert_ok!(mgate.read(&mut data, 0));
}

fn create_writeonly(t: &mut dyn WvTester) {
    let mgate = wv_assert_ok!(MemGate::new(0x1000, Perm::W));
    let mut data = [0u8; 8];
    wv_assert_err!(t, mgate.read(&mut data, 0), Code::NoPerm);
    wv_assert_ok!(mgate.write(&data, 0));
}

fn derive(t: &mut dyn WvTester) {
    let mgate = wv_assert_ok!(MemGate::new(0x1000, Perm::RW));
    wv_assert_err!(t, mgate.derive(0x0, 0x2000, Perm::RW), Code::InvArgs);
    wv_assert_err!(t, mgate.derive(0x1000, 0x10, Perm::RW), Code::InvArgs);
    wv_assert_err!(t, mgate.derive(0x800, 0x1000, Perm::RW), Code::InvArgs);
    let dgate = wv_assert_ok!(mgate.derive(0x800, 0x800, Perm::R));
    let mut data = [0u8; 8];
    wv_assert_err!(t, dgate.write(&data, 0), Code::NoPerm);
    wv_assert_ok!(dgate.read(&mut data, 0));
}

fn read_write(t: &mut dyn WvTester) {
    let mgate = wv_assert_ok!(MemGate::new(0x1000, Perm::RW));
    let refdata = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut data = [0u8; 8];
    wv_assert_ok!(mgate.write(&refdata, 0));
    wv_assert_ok!(mgate.read(&mut data, 0));
    wv_assert_eq!(t, data, refdata);

    wv_assert_ok!(mgate.read(&mut data[0..4], 4));
    wv_assert_eq!(t, &data[0..4], &refdata[4..8]);
    wv_assert_eq!(t, &data[4..8], &refdata[4..8]);
}

fn read_write_object(t: &mut dyn WvTester) {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Test {
        a: u32,
        b: u64,
        c: bool,
    }

    let mgate = wv_assert_ok!(MemGate::new(0x1000, Perm::RW));
    let refobj = Test {
        a: 0x1234,
        b: 0xF000_F000_AAAA_BBBB,
        c: true,
    };

    wv_assert_ok!(mgate.write_obj(&refobj, 0));
    let obj: Test = wv_assert_ok!(mgate.read_obj(0));

    wv_assert_eq!(t, refobj, obj);
}

fn remote_access(t: &mut dyn WvTester) {
    static mut _OBJ: u64 = 0;
    let sem1 = wv_assert_ok!(Semaphore::create(0));
    let sem2 = wv_assert_ok!(Semaphore::create(0));

    let tile = wv_assert_ok!(Tile::get("compat"));
    let mut child = wv_assert_ok!(ChildActivity::new(tile, "child"));

    let virt = if child.tile_desc().has_virtmem() {
        let virt = VirtAddr::new(0x3000_0000);
        // creating mapping in the child
        wv_assert_ok!(child.pager().unwrap().map_anon(
            virt,
            cfg::PAGE_SIZE,
            Perm::RW,
            MapFlags::PRIVATE
        ));
        // another mapping that is not touched by the child
        wv_assert_ok!(child.pager().unwrap().map_anon(
            virt + cfg::PAGE_SIZE,
            cfg::PAGE_SIZE,
            Perm::RW,
            MapFlags::PRIVATE
        ));
        virt
    }
    else {
        VirtAddr::from(unsafe { addr_of!(_OBJ) as *const _ })
    };

    wv_assert_ok!(child.delegate_obj(sem1.sel()));
    wv_assert_ok!(child.delegate_obj(sem2.sel()));

    let mut dst = child.data_sink();
    dst.push(virt);
    dst.push(sem1.sel());
    dst.push(sem2.sel());

    let mut act = wv_assert_ok!(child.run(|| {
        let mut src = Activity::own().data_source();
        let virt: VirtAddr = src.pop().unwrap();
        let sem1_sel: Selector = src.pop().unwrap();
        let sem2_sel: Selector = src.pop().unwrap();

        let sem1 = Semaphore::bind(sem1_sel);
        let sem2 = Semaphore::bind(sem2_sel);
        // write value to own address space
        let obj_addr = virt.as_mut_ptr::<u64>();
        unsafe { *obj_addr = 0xDEAD_BEEF };
        //  notify parent that we're ready
        wv_assert_ok!(sem1.up());
        // wait for parent
        wv_assert_ok!(sem2.down());
        Ok(())
    }));

    // wait until child is ready
    wv_assert_ok!(sem1.down());

    // read object from his address space
    let obj_mem = wv_assert_ok!(act.activity_mut().get_mem(
        math::round_dn(virt, VirtAddr::from(cfg::PAGE_SIZE)),
        cfg::PAGE_SIZE as GlobOff,
        Perm::R
    ));
    let obj: u64 =
        wv_assert_ok!(obj_mem
            .read_obj((virt - math::round_dn(virt, VirtAddr::from(cfg::PAGE_SIZE))).as_goff()));
    wv_assert_eq!(t, obj, 0xDEAD_BEEF);

    // notify child that we're done
    wv_assert_ok!(sem2.up());

    wv_assert_ok!(act.wait());
}
