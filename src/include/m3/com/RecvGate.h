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
#include <base/util/Util.h>
#include <base/DTU.h>

#include <m3/com/Gate.h>
#include <m3/WorkLoop.h>

#include <functional>
#include <memory>

namespace m3 {

class GateIStream;
class SendGate;
class VPE;

/**
 * A receive gate is used to receive messages from send gates. To this end, it has a receive buffer
 * of a fixed message and total size. Multiple send gates can be created for one receive gate. After
 * a message has been received, the reply operation can be used to send a reply back to the sender.
 *
 * Receiving messages is possible by waiting for them using the wait() method. This approach is used
 * when, e.g., receiving a reply upon a sent message. Alternatively, one can start to listen to
 * received messages. In this case, a WorkLoop item is created.
 */
class RecvGate : public Gate {
    enum {
        FREE_BUF    = 1,
        FREE_EP     = 2,
    };

    class RecvGateWorkItem : public WorkItem {
    public:
        explicit RecvGateWorkItem(RecvGate *buf) noexcept : _buf(buf) {
        }

        virtual void work() override;

    protected:
        RecvGate *_buf;
    };

    explicit RecvGate(VPE &vpe, capsel_t cap, int order, uint flags) noexcept
        : Gate(RECV_GATE, cap, flags),
          _vpe(vpe),
          _buf(),
          _order(order),
          _free(FREE_BUF),
          _handler(),
          _workitem() {
    }
    explicit RecvGate(VPE &vpe, capsel_t cap, epid_t ep, void *buf, int order, int msgorder, uint flags);

public:
    using msghandler_t = std::function<void(GateIStream&)>;

    /**
     * @return the receive gate for system call replies
     */
    static RecvGate &syscall() noexcept {
        return _syscall;
    }
    /**
     * @return the receive gate for upcalls
     */
    static RecvGate &upcall() noexcept {
        return _upcall;
    }
    /**
     * @return the default receive gate. can be used whenever a buffer for a single message with a
     *  reasonable size is sufficient
     */
    static RecvGate &def() noexcept {
        return _default;
    }

    /**
     * @return an invalid receive, which can be passed as reply gate to a send gate
     *  that is not interested in actual replies, but only wants to get its credits back.
     */
    static RecvGate &invalid() noexcept {
        return _invalid;
    }

    /**
     * Creates a new receive gate with given size.
     *
     * @param order the size of the buffer (2^<order> bytes)
     * @param msgorder the size of messages within the buffer (2^<msgorder> bytes)
     * @return the receive gate
     */
    static RecvGate create(int order, int msgorder);
    /**
     * Creates a new receive gate at selector <sel> with given size.
     *
     * @param sel the capability selector to use
     * @param order the size of the buffer (2^<order> bytes)
     * @param msgorder the size of messages within the buffer (2^<msgorder> bytes)
     * @return the receive gate
     */
    static RecvGate create(capsel_t sel, int order, int msgorder);

    /**
     * Creates a new receive gate that should be activated for <vpe>.
     *
     * @param vpe the VPE that should activate the receive gate
     * @param order the size of the buffer (2^<order> bytes)
     * @param msgorder the size of messages within the buffer (2^<msgorder> bytes)
     * @return the receive gate
     */
    static RecvGate create_for(VPE &vpe, int order, int msgorder);
    /**
     * Creates a new receive gate at selector <sel> that should be activated for <vpe>.
     *
     * @param vpe the VPE that should activate the receive gate
     * @param sel the capability selector to use
     * @param order the size of the buffer (2^<order> bytes)
     * @param msgorder the size of messages within the buffer (2^<msgorder> bytes)
     * @return the receive gate
     */
    static RecvGate create_for(VPE &vpe, capsel_t sel, int order, int msgorder, uint flags = 0);

    /**
     * Binds the receive gate at selector <sel>.
     *
     * @param sel the capability selector
     * @param order the size of the buffer (2^<order> bytes)
     * @param ep the endpoint it has already been activated to
     * @return the receive gate
     */
    static RecvGate bind(capsel_t sel, int order, epid_t ep = EP_COUNT) noexcept;

    RecvGate(const RecvGate&) = delete;
    RecvGate &operator=(const RecvGate&) = delete;
    RecvGate(RecvGate &&r) noexcept
            : Gate(std::move(r)),
              _vpe(r._vpe),
              _buf(r._buf),
              _order(r._order),
              _free(r._free),
              _handler(r._handler),
              _workitem(std::move(r._workitem)) {
        r._free = 0;
        r._workitem = nullptr;
    }
    ~RecvGate();

    /**
     * @return the buffer address
     */
    const void *addr() const noexcept {
        return _buf;
    }

    /**
     * Activates this receive gate, i.e., lets the kernel configure a free endpoint for it
     */
    void activate();
    /**
     * Activates this receive gate, i.e., lets the kernel configure endpoint <ep> for it
     */
    void activate(epid_t ep);
    /**
     * Activates this receive gate, i.e., lets the kernel configure endpoint <ep> for it and use
     * <addr> as the buffer.
     */
    void activate(epid_t ep, uintptr_t addr);

    /**
     * Deactivates and stops the receive gate.
     */
    void deactivate() noexcept;

    /**
     * Starts to listen for received messages, i.e., adds an item to the given workloop.
     *
     * @param wl the workloop
     * @param handler the handler to call for received messages
     */
    void start(WorkLoop *wl, msghandler_t handler);

    /**
     * Stops to listen for received messages
     */
    void stop() noexcept;

    /**
     * Fetches a message from this receive gate and returns it, if there is any.
     *
     * @return the message or nullptr
     */
    const DTU::Message *fetch() {
        activate();
        return DTU::get().fetch_msg(ep());
    }

    /**
     * Waits until a message is received. If <sgate> is given, it will stop if as soon as <sgate>
     * gets invalid and throw an exception.
     *
     * @param sgate the send gate (optional), if waiting for a reply
     * @return the fetched message
     */
    const DTU::Message *wait(SendGate *sgate);

    /**
     * Replies the <len> bytes at <reply> to the message <msg>.
     *
     * @param reply the reply message to send
     * @param len the length of the data
     * @param msg the message to reply to
     */
    void reply(const void *reply, size_t len, const DTU::Message *msg);

    /**
     * Drops all messages with given label. That is, these messages will be marked as read.
     *
     * @param label the label
     */
    void drop_msgs_with(label_t label) noexcept {
        DTU::get().drop_msgs(ep(), label);
    }

private:
    static void *allocate(VPE &vpe, epid_t ep, size_t size);
    static void free(void *);

    VPE &_vpe;
    void *_buf;
    int _order;
    uint _free;
    msghandler_t _handler;
    std::unique_ptr<RecvGateWorkItem> _workitem;
    static RecvGate _syscall;
    static RecvGate _upcall;
    static RecvGate _default;
    static RecvGate _invalid;
};

}
