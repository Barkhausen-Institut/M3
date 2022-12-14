/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

#include <base/Common.h>
#include <base/Env.h>
#include <base/TileDesc.h>
#include <base/stream/Serial.h>

#include <string.h>

class StandaloneEnvBackend : public m3::EnvBackend {
public:
    explicit StandaloneEnvBackend() {
    }

    virtual void init() override {
        m3::Serial::init("standalone", m3::TileId::from_raw(m3::env()->tile_id));
    }

    virtual void exit(m3::Errors::Code) override {
        m3::Machine::shutdown();
    }
};

extern void *_bss_end;

void m3::Env::init() {
    env()->set_backend(new StandaloneEnvBackend());
    env()->backend()->init();
    env()->call_constr();
}
