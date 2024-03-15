#
# Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
# Economic rights: Technische Universitaet Dresden (Germany)
#
# Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
#
# This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
#
# M3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# M3 is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License version 2 for more details.
#

#include <base/Asm.h>

BEGIN_FUNC(gem5_shutdown)
    .long 0x4200007B
1:  j     1b
END_FUNC(gem5_shutdown)

BEGIN_FUNC(gem5_writefile)
    .long 0x9E00007B
    ret
END_FUNC(gem5_writefile)

BEGIN_FUNC(gem5_readfile)
    .long 0xA000007B
    ret
END_FUNC(gem5_readfile)

BEGIN_FUNC(gem5_resetstats)
    .long   0x8000007B
    ret
END_FUNC(gem5_resetstats)

BEGIN_FUNC(gem5_dumpstats)
    .long   0x8100007B
    ret
END_FUNC(gem5_dumpstats)
