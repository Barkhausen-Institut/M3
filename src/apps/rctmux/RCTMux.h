/**
 * Copyright (C) 2015-2016, René Küttner <rene.kuettner@.tu-dresden.de>
 * Economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of M3 (Microkernel for Minimalist Manycores).
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
#include <base/Config.h>
#include <base/Exceptions.h>
#include <base/RCTMux.h>

namespace RCTMux {

namespace Arch {

void init();
void *init_state(m3::Exceptions::State *state);
void stop_state(m3::Exceptions::State *state);

}

void *ctxsw_protocol(void *s);

EXTERN_C void init();
EXTERN_C void sleep();

} /* namespace RCTMux */
