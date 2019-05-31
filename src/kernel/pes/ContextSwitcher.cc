/*
 * Copyright (C) 2015, René Küttner <rene.kuettner@tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

#include <base/RCTMux.h>
#include <base/log/Kernel.h>
#include <base/util/Time.h>

#include "pes/ContextSwitcher.h"
#include "pes/Timeouts.h"
#include "pes/PEManager.h"
#include "pes/VPEManager.h"
#include "pes/VPE.h"
#include "Args.h"
#include "DTU.h"
#include "Platform.h"

namespace kernel {

static const char *stateNames[] = {
    "S_IDLE",
    "S_STORE_WAIT",
    "S_STORE_DONE",
    "S_SWITCH",
    "S_RESTORE_WAIT",
    "S_RESTORE_DONE",
};

/**
 * The state machine for context switching looks as follows:
 *
 *          switch & cur     +----------+
 *         /-----------------|  S_IDLE  |<--------------\
 *         |                 +----------+               |
 *         v                     |   |                  |
 * +------------------+          |   |         +-----------------+
 * |   S_STORE_WAIT   |   switch |   |         |  S_RESTORE_DONE |
 * |   ------------   |     &    |   |         |  -------------- |
 * |   e/ inject IRQ  |    !cur  |   |         |    e/ notify    |
 * +------------------+          |   | start   +-----------------+
 *         |                     |   |                  ^
 *         | signal              |   |                  | signal
 *         |                     |   |                  |
 *         v                     |   |                  |
 * +------------------+          |   |         +-----------------+
 * |   S_STORE_DONE   |          |   |         |  S_RESTORE_WAIT |
 * |   ------------   |          |   \-------->|  -------------- |
 * | e/ save DTU regs |          |             |    e/ wakeup    |
 * +------------------+          |             +-----------------+
 *         |                     v                      ^
 *         |             +------------------+           |
 *         |             |     S_SWITCH     |           |
 *         \------------>|     --------     |-----------/
 *                       | e/ sched & reset |
 *                       +------------------+
 */

size_t ContextSwitcher::_global_ready[m3::isa_count()];

ContextSwitcher::ContextSwitcher(peid_t pe)
    : _muxable(Platform::pe(pe).supports_ctxsw()),
      _pe(pe),
      _isa(static_cast<size_t>(Platform::pe(pe).isa())),
      _state(S_IDLE),
      _count(),
      _pinned(0),
      _ready(),
      _timeout(),
      _wait_time(),
      _idle(),
      _cur(),
      _set_yield() {
    assert(pe > 0);
}

void ContextSwitcher::schedule() {
    if (_ready.length() > 0) {
        VPE *old = _cur;

        // find the next VPE to schedule
        _cur = nullptr;
        VPE *prev = nullptr;
        for(auto v = _ready.begin(); v != _ready.end(); ++v) {
            if(v->_group) {
                // first check if we can unblock all VPEs of the group at the same time
                bool unblock_now = true;
                for(auto gvpe = v->_group->begin(); gvpe != v->_group->end(); ++gvpe) {
                    if(gvpe->vpe != &*v && !PEManager::get().can_unblock_now(gvpe->vpe)) {
                        KLOG(CTXSW, "CtxSw[" << _pe << "] no sched of " << v->id()
                            << ", " << gvpe->vpe->id() << " not unblockable");
                        unblock_now = false;
                        break;
                    }
                }
                // ok, try the next one. and don't schedule the same VPE again
                if(&*v == old || !unblock_now) {
                    prev = &*v;
                    continue;
                }
            }

            // found a VPE to schedule
            _ready.remove(prev, &*v);
            _cur = &*v;
            break;
        }

        if(_cur) {
            _global_ready[_isa]--;
            assert(_cur->_flags & VPE::F_READY);
            _cur->_flags ^= VPE::F_READY;

            // unblock all other VPEs of the group
            if(_cur->_group) {
                for(auto gvpe = _cur->_group->begin(); gvpe != _cur->_group->end(); ++gvpe) {
                    if(gvpe->vpe != _cur) {
                        KLOG(CTXSW, "CtxSw[" << _pe << "] gangscheduling VPE " << gvpe->vpe->id());
                        PEManager::get().unblock_vpe(gvpe->vpe, true);
                    }
                }
            }
        }
        else
            _cur = _idle;
    }
    else
        _cur = _idle;
}

void ContextSwitcher::init() {
    assert(_idle == nullptr);

#if !defined(__host__)
    _idle = new VPE(m3::String("rctmux"), _pe, VPEManager::get().get_id(),
        VPE::F_IDLE | VPE::F_INIT, VPE::INVALID_EP, m3::KIF::INV_SEL);

    KLOG(CTXSW, "CtxSw[" << _pe << "] initialized (idle="
        << _idle->id() << ", muxable=" << _muxable << ")");
#endif

    if(_idle && _cur == nullptr)
        start_switch();
}

void ContextSwitcher::enqueue(VPE *vpe) {
    // never make IDLE VPEs ready
    if(vpe->_flags & (VPE::F_READY | VPE::F_IDLE))
        return;

    vpe->_flags |= VPE::F_READY;
    _ready.append(vpe);
    _global_ready[_isa]++;
}

void ContextSwitcher::dequeue(VPE *vpe) {
    if(!(vpe->_flags & VPE::F_READY))
        return;

    vpe->_flags ^= VPE::F_READY;
    _ready.remove(vpe);
    _global_ready[_isa]--;
}

void ContextSwitcher::add_vpe(VPE *vpe) {
    if(!(vpe->_flags & VPE::F_MUXABLE))
        _muxable = false;
    if(vpe->_flags & VPE::F_PINNED)
        _pinned++;

    _count++;
}

void ContextSwitcher::remove_vpe(VPE *vpe, bool migrate) {
    stop_vpe(vpe, true, migrate);

    if(--_count == 0)
        _muxable = Platform::pe(_pe).supports_ctxsw();
    if(vpe->_flags & VPE::F_PINNED)
        _pinned--;

    if(_count == 1) {
        // cancel timeout; the remaining VPE can run as long as it likes
        if(_timeout) {
            Timeouts::get().cancel(_timeout);
            _timeout = nullptr;
        }
    }
}

VPE *ContextSwitcher::steal_vpe() {
    if(can_mux() && _ready.length() > 0) {
        VPE *vpe = _ready.remove_if([](VPE *v) {
            return !v->is_pinned();
        });
        if(vpe) {
            if(_cur)
                DTU::get().flush_cache(_cur->desc());
            vpe->_flags ^= VPE::F_READY;
            _global_ready[_isa]--;
            return vpe;
        }
    }

    return nullptr;
}

void ContextSwitcher::start_vpe(VPE *vpe) {
    if(_cur != vpe) {
        unblock_vpe(vpe, false);
        return;
    }

    if(_state != S_IDLE) {
        // make sure that we don't get blocked
        vpe->_flags |= VPE::F_NOBLOCK;
        return;
    }

    m3::Time::start(0xcccc);
    _state = S_RESTORE_WAIT;
    next_state(0);
}

void ContextSwitcher::stop_vpe(VPE *vpe, bool force, bool migrate) {
    dequeue(vpe);

    if(_cur) {
        // ensure that all PTEs are in memory
        DTU::get().flush_cache(_cur->desc());
    }

    if(_cur == vpe && !migrate) {
        // for non-programmable accelerator, we have to do the save first, because we cannot
        // interrupt the accelerator at arbitrary points in time (this might screw up his FSM)
        if(force || Platform::pe(_pe).is_programmable()) {
            // the VPE id is expected to be invalid in S_SWITCH
            DTU::get().kill_vpe(_cur->desc());
            vpe->_state = VPE::SUSPENDED;
            _cur = nullptr;
        }
        // it is possible that we already started to save the state of <vpe>. we are no longer
        // interested in that, so just switch to someone else
        if(_state != S_IDLE) {
            assert(_state == S_STORE_DONE);
            _state = S_IDLE;
        }
        // don't switch to someone else if the group is still running
        if(!(vpe->_group && vpe->_group->has_other_app(vpe))) {
            // if there is no one ready on this PE and we have a group, check if there is someone
            // ready on one of the VPEs of the group.
            if(vpe->_group && _ready.length() == 0) {
                for(auto gvpe = vpe->_group->begin(); gvpe != vpe->_group->end(); ++gvpe) {
                    if(gvpe->vpe != vpe && PEManager::get().yield(gvpe->vpe->pe()))
                        return;
                }
            }
            else
                start_switch();
        }
    }
}

bool ContextSwitcher::yield_vpe(VPE *vpe) {
    if(_cur != vpe)
        return false;
    if(_ready.length() == 0)
        return false;
    if(vpe->_group && !vpe->_group->all_yielded())
        return false;

    start_switch();
    return true;
}

bool ContextSwitcher::current_is_idling() const {
    return !_cur || (_cur->_flags & (VPE::F_IDLE | VPE::F_YIELDED)) || !_cur->has_app() ||
        (!_cur->_group && _cur->is_waiting());
}

bool ContextSwitcher::can_unblock_now(VPE *vpe) {
    // if it's already running, it's fine too
    if(_cur == vpe)
        return true;
    // if the VPE is not waiting and not ready, just make it ready. this is required, because the
    // VPEs within a group might communicate with each other and might be waiting for another VPE
    // in the group
    if(!vpe->is_waiting() && !(vpe->_flags & VPE::F_READY)) {
        // always put it to the front
        vpe->_flags |= VPE::F_READY;
        _global_ready[_isa]++;
        _ready.insert(nullptr, vpe);
        return true;
    }
    // if it's not the first VPE in the list, don't schedule it now
    if(_ready.length() > 0 && _ready.begin()->id() != vpe->id())
        return false;
    return !vpe->is_waiting();
}

bool ContextSwitcher::can_switch() const {
    if(current_is_idling())
        return true;

    if(!_timeout) {
        uint64_t now = DTU::get().get_time();
        uint64_t exectime = now - _cur->_lastsched;
        // if there is some time left in the timeslice, program a timeout
        if(exectime >= Args::timeslice)
            return true;
    }
    return false;
}

bool ContextSwitcher::unblock_vpe(VPE *vpe, bool force) {
#if defined(__host__)
    // on host, just wait until the VPE did the init syscall
    if(_cur == vpe && vpe->state() == VPE::SUSPENDED)
        return false;
#endif

    if(_cur == vpe)
        return true;

    enqueue(vpe);

    if(force || current_is_idling())
        return start_switch();

    if(!_timeout) {
        uint64_t now = DTU::get().get_time();
        uint64_t exectime = now - _cur->_lastsched;
        // if there is some time left in the timeslice, program a timeout
        if(exectime < Args::timeslice) {
            auto &&callback = std::bind(&ContextSwitcher::start_switch, this, true);
            _timeout = Timeouts::get().wait_for(Args::timeslice - exectime, m3::Util::move(callback));
        }
        // otherwise, switch now
        else
            return start_switch();
    }

    // wait for the timeout
    return false;
}

void ContextSwitcher::update_yield() {
    // if a context switch is in progress, leave it alone
    if(_state != S_IDLE)
        return;

    bool yield = _global_ready[_isa] > 0;
    if(can_mux() && _cur && !(_cur->_flags & VPE::F_IDLE) && yield != _set_yield) {
        KLOG(CTXSW, "CtxSw[" << _pe << "]: VPE " << _cur->id() << " updating yield=" << yield);

        // update yield time and wake him up in case he was idling
        _set_yield = yield;
        uint64_t val = yield ? _cur->yield_time() : 0;
        DTU::get().write_mem(_cur->desc(), RCTMUX_YIELD, &val, sizeof(val));
        if(yield)
            DTU::get().inject_irq(_cur->desc());
    }
}

bool ContextSwitcher::start_switch(bool timedout) {
    if(!timedout && _timeout)
        Timeouts::get().cancel(_timeout);
    _timeout = nullptr;

    // if there is nobody to switch to, just ignore it
    if(_cur && _ready.length() == 0)
        return false;
    // if there is a switch running, do nothing
    if(_state != S_IDLE)
        return false;

    m3::Time::start(0xcccc);

    // if no VPE is running, directly switch to a new VPE
    if (_cur == nullptr)
        _state = S_SWITCH;
    else
        _state = S_STORE_WAIT;

    bool finished = next_state(0);
    if(finished)
        m3::Time::stop(0xcccc);
    return finished;
}

void ContextSwitcher::continue_switch() {
    assert(_state == S_STORE_DONE || _state == S_RESTORE_DONE);
    if(!_cur)
        return;

    uint64_t flags = 0;
    DTU::get().read_swflags(_cur->desc(), &flags);

    if(~flags & m3::RCTMuxCtrl::SIGNAL) {
        assert(_wait_time > 0);
        if(_wait_time < MAX_WAIT_TIME)
            _wait_time *= 2;
        Timeouts::get().wait_for(_wait_time, std::bind(&ContextSwitcher::continue_switch, this));
    }
    else {
        if(next_state(flags))
            m3::Time::stop(0xcccc);
    }
}

bool ContextSwitcher::next_state(uint64_t flags) {
retry:
    KLOG(CTXSW_STATES, "CtxSw[" << _pe << "]: next; state="
        << stateNames[static_cast<size_t>(_state)]
        << " (current=" << (_cur ? _cur->id() : 0) << ":"
                        << (_cur ? _cur->name().c_str() : "-") << ")");

    _wait_time = 0;

    VPE *migvpe = nullptr;
    switch(_state) {
        case S_IDLE:
            assert(false);
            break;

        case S_STORE_WAIT: {
            DTU::get().write_swflags(_cur->desc(), m3::RCTMuxCtrl::STORE | m3::RCTMuxCtrl::WAITING);
            DTU::get().inject_irq(_cur->desc());

            _state = S_STORE_DONE;

            _wait_time = INIT_WAIT_TIME;
            break;
        }

        case S_STORE_DONE: {
            _cur->_dtustate.save(_cur->desc(), _cur->_headers);

            uint64_t now = DTU::get().get_time();
            uint64_t cycles = _cur->_dtustate.get_idle_time();
            uint64_t total = now - _cur->_lastsched;
            bool blocked = _cur->is_waiting() || !(_cur->_flags & VPE::F_HASAPP) ||
                           (!(_cur->_flags & VPE::F_NOBLOCK) && _cur->_dtustate.was_idling());
            _cur->_flags &= ~static_cast<uint>(VPE::F_NOBLOCK);

            KLOG(CTXSW, "CtxSw[" << _pe << "]: saved VPE " << _cur->id() << " (idled "
                << cycles << " of " << total << " cycles)");
            KLOG(CTXSW, "CtxSw[" << _pe << "]: VPE " << _cur->id() << " is set to "
                << (blocked ? "blocked" : "ready"));

            _cur->_state = VPE::SUSPENDED;
            _cur->_flags &= ~static_cast<uint>(VPE::F_FLUSHED);
            if(!blocked) {
                // the VPE is ready, so try to migrate it somewhere else to continue immediately
                if(!_cur->migrate(false))
                    enqueue(_cur);
                // if that worked, remember to switch to it. don't do that now, because we have to
                // do the reset first to ensure that the cache is flushed in case of non coherent
                // caches.
                else
                    migvpe = _cur;
            }

            [[fallthrough]];
        }

        case S_SWITCH: {
            vpeid_t old = _cur ? _cur->id() : VPE::INVALID_ID;
            schedule();
            if(_cur == nullptr) {
                _state = S_IDLE;
                return true;
            }

            // make it resuming here, so that the PTEs are sent to the PE, if F_INIT is set
            // but we do not yet allow other VPEs to access this VPE
            _cur->_state = VPE::RESUMING;
            _cur->_lastsched = DTU::get().get_time();

            _cur->_dtustate.reset(RCTMUX_ENTRY, _cur->_flags & VPE::F_NEEDS_INVAL);
            _cur->_flags &= ~static_cast<uint>(VPE::F_NEEDS_INVAL | VPE::F_FLUSHED | VPE::F_YIELDED);

            // set address space properties first to load them during the restore
            if((_cur->_flags & VPE::F_INIT) && _cur->address_space()) {
                AddrSpace *as = _cur->address_space();
                _cur->_dtustate.config_pf(as->root_pt(), as->sep(), as->rep());
            }
            _cur->_dtustate.restore(VPEDesc(_pe, old), _cur->_headers, _cur->id());

            if(_cur->_flags & VPE::F_INIT)
                _cur->init_memory();

            [[fallthrough]];
        }

        case S_RESTORE_WAIT: {
            // let the VPE report idle times if there are other VPEs
            uint64_t report = (can_mux() && _global_ready[_isa] > 0) ? _cur->yield_time() : 0;
            uint64_t flags = m3::RCTMuxCtrl::WAITING;
            _set_yield = report > 0;

            // tell rctmux whether there is an application and the PE id
            if(_cur->_flags & VPE::F_HASAPP)
                flags |= m3::RCTMuxCtrl::RESTORE | (static_cast<uint64_t>(_pe) << 32);

            KLOG(CTXSW, "CtxSw[" << _pe << "]: restoring VPE " << _cur->id() << " with report="
                << report << " flags=" << m3::fmt(flags, "#x"));

            DTU::get().write_swstate(_cur->desc(), flags, report);
            DTU::get().inject_irq(_cur->desc());
            _state = S_RESTORE_DONE;

            _wait_time = INIT_WAIT_TIME;
            break;
        }

        case S_RESTORE_DONE: {
#if !defined(__host__)
            // we have finished the init phase (if it was set)
            _cur->_flags &= ~static_cast<uint>(VPE::F_INIT);
            // now that everything is complete, enable the communication
            _cur->_dtustate.enable_communication(_cur->desc());
            _cur->_state = VPE::RUNNING;
            _cur->notify_resume();
#else
            // on host, we will set it to running after the VPECTRL_INIT syscall
            _cur->_state = VPE::SUSPENDED;
#endif

            DTU::get().write_swflags(_cur->desc(), 0);
            _state = S_IDLE;

            // if we are starting a VPE, we might already have a timeout for it
            if(_ready.length() > 0 && !_timeout) {
                auto &&callback = std::bind(&ContextSwitcher::start_switch, this, true);
                _timeout = Timeouts::get().wait_for(Args::timeslice, m3::Util::move(callback));
            }
            break;
        }
    }

    KLOG(CTXSW_STATES, "CtxSw[" << _pe << "]: done; state="
        << stateNames[static_cast<size_t>(_state)]
        << " (current=" << (_cur ? _cur->id() : 0) << ":"
                        << (_cur ? _cur->name().c_str() : "-") << ")");

    if(migvpe)
        PEManager::get().unblock_vpe(migvpe, false);

    if(_wait_time) {
        int count = _cur->_group ? 1 : SIGNAL_WAIT_COUNT;
        for(int i = 0; i < count; ++i) {
            DTU::get().read_swflags(_cur->desc(), &flags);
            if(flags & m3::RCTMuxCtrl::SIGNAL)
                goto retry;
        }

        Timeouts::get().wait_for(_wait_time, std::bind(&ContextSwitcher::continue_switch, this));
    }

    return _state == S_IDLE;
}

} /* namespace m3 */
