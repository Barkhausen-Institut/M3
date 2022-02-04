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

#include <base/Common.h>
#include <base/col/SList.h>

#include <m3/com/EP.h>

namespace m3 {

class Gate;
class RecvGate;
class VPE;

/**
 * The endpoint manager allows us to have more gates than endpoints by multiplexing
 * the endpoints among the gates.
 */
class EPMng {
    friend class Gate;
    friend class RecvGate;
    friend class VPE;

public:
    explicit EPMng(VPE &vpe)
        : _vpe(vpe),
          _eps() {
    }

    /**
     * Acquires a new endpoint.
     *
     * @param ep the endpoint number (default = any)
     * @param replies the number of reply slots (default = 0)
     * @return the endpoint
     */
    EP *acquire(epid_t ep = TOTAL_EPS, uint replies = 0);

    /**
     * Releases the given endpoint. If <invalidate> is true, the endpoint will be invalidate.
     *
     * @param ep the endpoint
     * @param invalidate whether to invalidate the EP
     */
    void release(EP *ep, bool invalidate) noexcept;

private:
    VPE &_vpe;
    SList<EP> _eps;
};

}
