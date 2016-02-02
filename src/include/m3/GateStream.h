/*
 * Copyright (C) 2015, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/util/Util.h>
#include <m3/util/String.h>
#include <m3/util/Math.h>
#include <m3/cap/SendGate.h>
#include <m3/cap/MemGate.h>
#include <m3/cap/RecvGate.h>
#include <m3/tracing/Tracing.h>
#include <m3/Marshalling.h>
#include <m3/DTU.h>
#include <m3/Heap.h>
#include <assert.h>

namespace m3 {

/**
 * The gate stream classes provide an easy abstraction to marshall or unmarshall data when
 * communicating between VPEs. Therefore, if you want to combine multiple values into a single
 * message or extract multiple values from a message, this is the abstraction you might want to use.
 * If you already have the data to send, you should directly use the send-method of SendGate. If
 * you don't want to extract values from a message but directly access the message, use the
 * data-field of the message you received.
 *
 * All classes work with (variadic) templates and are thus type-safe. Of course, that does not
 * relieve you from taking care that sender and receiver agree on the types of the values that are
 * exchanged via messaging.
 */

class GateIStream;

/**
 * The gate stream to marshall values into a message and send it over an endpoint. Thus, it "outputs"
 * values into a message.
 */
class GateOStream : public Marshaller {
public:
    explicit GateOStream(unsigned char *bytes, size_t total) : Marshaller(bytes, total) {
    }
    GateOStream(const GateOStream &) = default;
    GateOStream &operator=(const GateOStream &) = default;

    /**
     * Sends the current content of this GateOStream as a message to the given gate.
     *
     * @param gate the gate to send to
     * @return the error code or Errors::NO_ERROR
     */
    Errors::Code send(SendGate &gate) {
        return gate.send(bytes(), total());
    }
    /**
     * Replies the current content of this GateOStream as a message to the first not acknowledged
     * message in the receive buffer of given receive gate.
     *
     * @param gate the gate that hosts the message to reply to
     * @return the error code or Errors::NO_ERROR
     */
    Errors::Code reply(RecvGate &gate) {
        return gate.reply_sync(bytes(), total(), DTU::get().get_msgoff(gate.epid(), &gate));
    }
    /**
     * Writes the current content of this GateOStream to <offset> in the given memory area.
     *
     * @param gate the memory gate to write to
     * @param offset the offset within the area the gate points to
     * @return the error code or Errors::NO_ERROR
     */
    Errors::Code write(MemGate &gate, size_t offset) {
        return gate.write_sync(bytes(), total(), offset);
    }

    /**
     * Receives a message from the given receive gate and returns an gate input stream for it.
     *
     * @param gate the receive gate
     * @return the GateIStream to unmarshall the message
     */
    GateIStream receive(RecvGate &gate);

    using Marshaller::put;

    /**
     * Puts all remaining items (the ones that haven't been read yet) of <is> into this GateOStream.
     *
     * @param is the GateIStream
     * @return *this
     */
    void put(const GateIStream &is);
};

/**
 * An implementation of GateOStream that hosts the message as a member. E.g. you can put an object
 * of this class on the stack, which would host the message on the stack.
 * In most cases, you don't want to use this class yourself, but the free-standing convenience
 * functions below that automatically determine <SIZE>.
 *
 * @param SIZE the max. size of the message
 */
template<size_t SIZE>
class StaticGateOStream : public GateOStream {
public:
    explicit StaticGateOStream() : GateOStream(_bytes, SIZE) {
    }
    template<size_t SRCSIZE>
    StaticGateOStream(const StaticGateOStream<SRCSIZE> &os) : GateOStream(os) {
        static_assert(SIZE >= SRCSIZE, "Incompatible sizes");
        memcpy(_bytes, os._bytes, sizeof(os._bytes));
    }
    template<size_t SRCSIZE>
    StaticGateOStream &operator=(const StaticGateOStream<SRCSIZE> &os) {
        static_assert(SIZE >= SRCSIZE, "Incompatible sizes");
        GateOStream::operator=(os);
        if(&os != this)
            memcpy(_bytes, os._bytes, sizeof(os._bytes));
        return *this;
    }

private:
    alignas(DTU_PKG_SIZE) unsigned char _bytes[SIZE];
};

/**
 * An implementation of GateOStream that hosts the message on the stack by using alloca.
 */
class AutoGateOStream : public GateOStream {
public:
#if defined(__t2__) or defined(__t3__)
    // TODO alloca() uses movsp which causes an exception to be handled appropriately. since this
    // isn't that trivial to implement, we're using malloc instead.
    explicit AutoGateOStream(size_t size)
        : GateOStream(static_cast<unsigned char*>(Heap::alloc(Math::round_up(size, DTU_PKG_SIZE))),
            Math::round_up(size, DTU_PKG_SIZE)) {
    }
    ~AutoGateOStream() {
        Heap::free(_bytes);
    }
#else
    ALWAYS_INLINE explicit AutoGateOStream(size_t size)
        : GateOStream(static_cast<unsigned char*>(alloca(Math::round_up(size, DTU_PKG_SIZE))),
            Math::round_up(size, DTU_PKG_SIZE)) {
    }
#endif

    AutoGateOStream(AutoGateOStream &&os)
        : GateOStream(os) {
    }

    /**
     * Claim the ownership of the data from this class. Thus, it will not free it.
     */
    void claim() {
        _bytes = nullptr;
    }
};

/**
 * The gate stream to unmarshall values from a message. Thus, it "inputs" values from a message
 * into variables.
 *
 * Note: unfortunately, we can't reuse the functionality of Unmarshaller here. It seems to be a
 * compiler-bug when building for Xtensa. The compiler generates wrong code when we initialize the
 * _length field to _msg->length.
 */
class GateIStream {
public:
    /**
     * Creates an object to read the first not acknowledged message from <gate>.
     *
     * @param gate the gate to fetch the message from
     * @param ack whether to acknowledge the message afterwards
     */
    explicit GateIStream(RecvGate &gate, Errors::Code err = Errors::NO_ERROR, bool ack = false)
        : _err(err), _ack(ack), _pos(0), _gate(&gate), _msg(DTU::get().message(gate.epid())) {
    }

    // don't do the ack twice. thus, copies never ack.
    GateIStream(const GateIStream &is)
        : _err(is._err), _ack(false), _pos(is._pos), _gate(is._gate), _msg(is._msg) {
    }
    GateIStream &operator=(const GateIStream &is) {
        if(this != &is) {
            _err = is._err;
            _ack = false;
            _pos = is._pos;
            _gate = is._gate;
            _msg = is._msg;
        }
        return *this;
    }
    GateIStream &operator=(GateIStream &&is) {
        if(this != &is) {
            _err = is._err;
            _ack = is._ack;
            _pos = is._pos;
            _gate = is._gate;
            _msg = is._msg;
            is._ack = false;
        }
        return *this;
    }
    GateIStream(GateIStream &&is)
        : _err(is._err), _ack(is._ack), _pos(is._pos), _gate(is._gate), _msg(is._msg) {
        is._ack = false;
    }
    ~GateIStream() {
        ack();
    }

    /**
     * @return the error that occurred (or Errors::NO_ERROR)
     */
    Errors::Code error() const {
        return _err;
    }
    /**
     * @return the message (header + payload)
     */
    const DTU::Message &message() const {
        return *_msg;
    }
    /**
     * @return the label of the message
     */
    label_t label() const {
        return _msg->label;
    }
    /**
     * @return the current position, i.e. the offset of the unread data
     */
    size_t pos() const {
        return _pos;
    }
    /**
     * @return the length of the message in bytes
     */
    size_t length() const {
#if defined(__t3__)
        return _msg->length * DTU_PKG_SIZE;
#else
        return _msg->length;
#endif
    }
    /**
     * @return the remaining bytes to read
     */
    size_t remaining() const {
        return length() - _pos;
    }
    /**
     * @return the message payload
     */
    const unsigned char *buffer() const {
        return _msg->data;
    }

    /**
     * Replies the message constructed by <os> to this message
     *
     * @param os the GateOStream hosting the message to reply
     * @return the error code or Errors::NO_ERROR
     */
    Errors::Code reply(const GateOStream &os) const {
        return reply(os.bytes(), os.total());
    }
    /**
     * Replies the given message to this one
     *
     * @param data the message data
     * @param len the length of the message
     * @return the error code or Errors::NO_ERROR
     */
    Errors::Code reply(const void *data, size_t len) const {
        return _gate->reply_sync(data, len, DTU::get().get_msgoff(_gate->epid(), _gate, _msg));
    }

    /**
     * Pulls the given values out of this stream
     *
     * @param val the value to write to
     * @param args the other values to write to
     */
    template<typename T, typename... Args>
    void vpull(T &val, Args &... args) {
        *this >> val;
        vpull(args...);
    }

    /**
     * Pulls a value into <value>.
     *
     * @param value the value to write to
     * @return *this
     */
    template<typename T>
    GateIStream & operator>>(T &value) {
        assert(_pos + sizeof(T) <= length());
        value = *reinterpret_cast<T*>(_msg->data + _pos);
        _pos += Math::round_up(sizeof(T), sizeof(ulong));
        return *this;
    }
    GateIStream & operator>>(String &value) {
        assert(_pos + sizeof(size_t) <= length());
        size_t len = *reinterpret_cast<size_t*>(_msg->data + _pos);
        _pos += sizeof(size_t);
        assert(_pos + len <= length());
        value.reset(reinterpret_cast<const char*>(_msg->data + _pos), len);
        _pos += Math::round_up(len, sizeof(ulong));
        return *this;
    }

    /**
     * Acknowledges this message, i.e. moves the read-position in the ringbuffer forward so that
     * we can receive new messages, possibly overwriting this one.
     */
    void ack() {
        if(_ack) {
            DTU::get().ack_message(_gate->epid());
            _ack = false;
        }
    }

private:
    // needed as recursion-end
    void vpull() {
    }

    Errors::Code _err;
    bool _ack;
    size_t _pos;
    RecvGate *_gate;
    DTU::Message *_msg;
};

inline GateIStream GateOStream::receive(RecvGate &gate) {
    Errors::Code err = gate.wait(nullptr);
    return GateIStream(gate, err, true);
}
inline void GateOStream::put(const GateIStream &is) {
    assert(fits(_bytecount, is.remaining()));
    memcpy(const_cast<unsigned char*>(bytes()) + _bytecount, is.buffer() + is.pos(), is.remaining());
    _bytecount += is.remaining();
}

/**
 * The following templates are used to determine the size of given values in order to construct
 * a StaticGateOStream object.
 */

template<typename T>
struct OStreamSize {
    static const size_t value = Math::round_up(sizeof(T), sizeof(ulong));
};
template<>
struct OStreamSize<String> {
    static const size_t value = String::DEFAULT_MAX_LEN;
};
template<>
struct OStreamSize<const char*> {
    static const size_t value = String::DEFAULT_MAX_LEN;
};

template<typename T>
constexpr size_t _ostreamsize() {
    return OStreamSize<T>::value;
}
template<typename T1, typename T2, typename... Args>
constexpr size_t _ostreamsize() {
    return OStreamSize<T1>::value + _ostreamsize<T2, Args...>();
}

/**
 * @return the size required for <T1> and <Args>.
 */
template<typename T1, typename... Args>
constexpr size_t ostreamsize() {
    return Math::round_up(_ostreamsize<T1, Args...>(), DTU_PKG_SIZE);
}

/**
 * @return the sum of the lengths <len> and <lens>, respecting alignment
 */
template<typename T>
constexpr size_t vostreamsize(T len) {
    return Math::round_up(len, sizeof(ulong));
}
template<typename T1, typename... Args>
constexpr size_t vostreamsize(T1 len, Args... lens) {
    return Math::round_up(
        Math::round_up(len, sizeof(ulong)) + vostreamsize<Args...>(lens...), DTU_PKG_SIZE);
}

static_assert(ostreamsize<int, float, int>() ==
    Math::round_up(sizeof(ulong) + sizeof(ulong) + sizeof(ulong), DTU_PKG_SIZE), "failed");
static_assert(ostreamsize<short, String>() ==
    Math::round_up(sizeof(ulong) + String::DEFAULT_MAX_LEN, DTU_PKG_SIZE), "failed");


/**
 * All these methods send the given data; either over <gate> or as an reply to the first not
 * acknowledged message in <gate> or as a reply on a GateIStream.
 *
 * @param gate the gate to send to
 * @param data the message data
 * @param len the message length
 * @return the error code or Errors::NO_ERROR
 */
static inline Errors::Code send_msg(SendGate &gate, const void *data, size_t len) {
    EVENT_TRACER_send_msg();
    return gate.send(data, len);
}
static inline Errors::Code reply_msg(RecvGate &gate, const void *data, size_t len) {
    EVENT_TRACER_reply_msg();
    return gate.reply_sync(data, len, DTU::get().get_msgoff(gate.epid(), &gate));
}
static inline Errors::Code reply_msg_on(const GateIStream &is, const void *data, size_t len) {
    EVENT_TRACER_reply_msg_on();
    return is.reply(data, len);
}

/**
 * Creates a StaticGateOStream for the given arguments.
 *
 * @return the stream
 */
template<typename ... Args>
static inline auto create_vmsg(const Args& ... args) -> StaticGateOStream<ostreamsize<Args...>()> {
    StaticGateOStream<ostreamsize<Args...>()> os;
    os.vput(args...);
    return os;
}

/**
 * All these methods put a message of the appropriate size, depending on the types of <args>, on the
 * stack, copies the values into it and sends it; either over <gate> or as an reply to the first not
 * acknowledged message in <gate> or as a reply on a GateIStream.
 *
 * @param gate the gate to send to
 * @param args the arguments to put into the message
 * @return the error code or Errors::NO_ERROR
 */
template<typename... Args>
static inline Errors::Code send_vmsg(SendGate &gate, const Args &... args) {
    EVENT_TRACER_send_vmsg();
    return create_vmsg(args...).send(gate);
}
template<typename... Args>
static inline Errors::Code reply_vmsg(RecvGate &gate, const Args &... args) {
    EVENT_TRACER_reply_vmsg();
    return create_vmsg(args...).reply(gate);
}
template<typename... Args>
static inline Errors::Code reply_vmsg_on(const GateIStream &is, const Args &... args) {
    EVENT_TRACER_reply_vmsg_on();
    return is.reply(create_vmsg(args...));
}

/**
 * Puts a message of the appropriate size, depending on the types of <args>, on the
 * stack, copies the values into it and writes it to <gate> at <offset>.
 *
 * @param gate the memory gate
 * @param offset the offset to write to
 * @param args the arguments to marshall
 * @return the error code or Errors::NO_ERROR
 */
template<typename... Args>
static inline Errors::Code write_vmsg(MemGate &gate, size_t offset, const Args &... args) {
    EVENT_TRACER_write_vmsg();
    return create_vmsg(args...).write(gate, offset);
}

/**
 * Receives a message from <gate> and returns an GateIStream to unmarshall the message. Note that
 * the GateIStream object acknowledges the message on destruction.
 *
 * @param gate the gate to receive the message from
 * @return the GateIStream
 */
static inline GateIStream receive_msg(RecvGate &gate) {
    EVENT_TRACER_receive_msg();
    Errors::Code err = gate.wait(nullptr);
    return GateIStream(gate, err, true);
}
/**
 * Receives a message from <gate> and unmarshalls the message into <args>. Note that
 * the GateIStream object acknowledges the message on destruction.
 *
 * @param gate the gate to receive the message from
 * @param args the arguments to unmarshall to
 * @return the GateIStream, e.g. to read further values or to reply
 */
template<typename... Args>
static inline GateIStream receive_vmsg(RecvGate &gate, Args &... args) {
    EVENT_TRACER_receive_vmsg();
    Errors::Code err = gate.wait(nullptr);
    GateIStream is(gate, err, true);
    is.vpull(args...);
    return is;
}

/**
 * Receives the reply for a message sent over <gate> and returns an GateIStream to unmarshall the
 * message. Note that the GateIStream object acknowledges the message on destruction.
 * The difference to receive_v?msg() is, that it
 *
 * @param gate the gate to receive the message from
 * @return the GateIStream
 */
static inline GateIStream receive_reply(SendGate &gate) {
    EVENT_TRACER_receive_msg();
    Errors::Code err = gate.receive_gate()->wait(&gate);
    return GateIStream(*gate.receive_gate(), err, true);
}

/**
 * Convenience methods that combine send_msg()/send_vmsg() and receive_msg().
 */
static inline GateIStream send_receive_msg(SendGate &gate, const void *data, size_t len) {
    EVENT_TRACER_send_receive_msg();
    send_msg(gate, data, len);
    return receive_reply(gate);
}
template<typename... Args>
static inline GateIStream send_receive_vmsg(SendGate &gate, const Args &... args) {
    EVENT_TRACER_send_receive_vmsg();
    send_vmsg(gate, args...);
    return receive_reply(gate);
}

}
