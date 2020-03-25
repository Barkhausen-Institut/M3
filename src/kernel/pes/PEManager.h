/*
 * Copyright (C) 2016-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#pragma once

#include <base/PEDesc.h>

#include "PEMux.h"

namespace kernel {

class VPE;
class KMemObject;

class PEManager {
public:
    static void create() {
        _inst = new PEManager();
    }
    static PEManager &get() {
        return *_inst;
    }

private:
    explicit PEManager();

public:
    peid_t find_pe(const m3::PEDesc &pe) const;

    PEMux *pemux(peid_t pe) {
        return _muxes[pe];
    }

    void add_vpe(VPECapability *vpe);
    void remove_vpe(VPE *vpe);

    void init_vpe(VPE *vpe);
    void start_vpe(VPE *vpe);
    void stop_vpe(VPE *vpe);

private:
    void deprivilege_pes() const;

    PEMux **_muxes;
    static PEManager *_inst;
};

}
