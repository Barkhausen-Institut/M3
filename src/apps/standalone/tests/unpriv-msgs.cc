/*
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

#include "../common.h"

using namespace m3;

static constexpr epid_t SEP = TCU::FIRST_USER_EP;
static constexpr epid_t REP = TCU::FIRST_USER_EP + 1;
static constexpr epid_t REP2 = TCU::FIRST_USER_EP + 2;
static constexpr epid_t RPLEP = TCU::FIRST_USER_EP + 3; // could be multiple EPs

static void test_msg_errors() {
    auto own_tile = TileId::from_raw(env()->tile_id);

    char buffer[2 * 64];
    uintptr_t buf1 = reinterpret_cast<uintptr_t>(&buffer);

    MsgBuf msg, empty_msg;
    msg.cast<uint64_t>() = 5678;

    logln("SEND without send EP"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, 3);
        ASSERT_EQ(kernel::TCU::send(REP, msg, 0x1111, TCU::NO_REPLIES), Errors::NO_SEP);
    }

    logln("SEND+ACK with invalid arguments"_cf);
    {
        kernel::TCU::config_send(SEP, 0x1234, own_tile, 1, 6 /* 64 */, 2);

        // message too large
        MsgBuf large_msg;
        large_msg.cast<uint8_t[1 + 64 - sizeof(TCU::Message::Header)]>();
        ASSERT_EQ(kernel::TCU::send(SEP, large_msg, 0x1111, TCU::NO_REPLIES),
                  Errors::OUT_OF_BOUNDS);
        // invalid reply EP
        ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, SEP), Errors::NO_REP);
        // not a receive EP
        ASSERT_EQ(kernel::TCU::ack_msg(SEP, 0, nullptr), Errors::NO_REP);
    }

    logln("REPLY+ACK with out-of-bounds message"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP);

        // reply on message that's out of bounds
        const TCU::Message *rmsg = reinterpret_cast<const TCU::Message *>(buf1 + (1 << 6));
        ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::INV_MSG_OFF);
        // ack message that's out of bounds
        ASSERT_EQ(kernel::TCU::ack_msg(REP, buf1, rmsg), Errors::INV_MSG_OFF);
    }

    logln("REPLY with disabled replies"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, TCU::NO_REPLIES);
        const TCU::Message *rmsg = reinterpret_cast<const TCU::Message *>(buf1);
        ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::REPLIES_DISABLED);
    }

    logln("REPLY with normal send EP"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP,
                                 1 /* make msg 0 (EP 2) occupied */, 0);
        kernel::TCU::config_send(RPLEP, 0x5678, own_tile, REP, 5 /* 32 */, 1);
        const TCU::Message *rmsg = reinterpret_cast<const TCU::Message *>(buf1);
        ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::SEND_REPLY_EP);
    }

    logln("SEND to invalid receive EP"_cf);
    {
        kernel::TCU::config_invalid(REP);
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP /* invalid REP */, 5 /* 32 */, 1);
        ASSERT_EQ(kernel::TCU::send(SEP, empty_msg, 0x1111, TCU::NO_REPLIES), Errors::RECV_GONE);
    }

    logln("SEND to out-of-bounds receive EP"_cf);
    {
        kernel::TCU::config_send(SEP, 0x5678, own_tile, TOTAL_EPS, 5 /* 32 */, 1);
        ASSERT_EQ(kernel::TCU::send(SEP, empty_msg, 0x1111, TCU::NO_REPLIES), Errors::RECV_GONE);
    }

    logln("SEND of too large message"_cf);
    {
        MsgBuf large_msg;
        large_msg.cast<uint64_t[4]>();
        kernel::TCU::config_recv(REP, buf1, 5 /* 32 */, 5 /* 32 */, TCU::NO_REPLIES);
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 6 /* 64 */, 1);
        ASSERT_EQ(kernel::TCU::send(SEP, large_msg, 0x1111, TCU::NO_REPLIES),
                  Errors::RECV_OUT_OF_BOUNDS);
    }

    logln("SEND without 16-byte aligned message"_cf);
    {
        ALIGNED(16) uint64_t words[2] = {0, 0};
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, TCU::NO_REPLIES);
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 6 /* 64 */, 1);
        ASSERT_EQ(kernel::TCU::send_aligned(SEP, words + 1, sizeof(uint64_t), 0x1111,
                                            TCU::NO_REPLIES),
                  Errors::MSG_UNALIGNED);
    }

    logln("REPLY without 16-byte aligned message"_cf);
    {
        ALIGNED(16) uint64_t words[2] = {0, 0};
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP, 1, 0);
        kernel::TCU::config_send(RPLEP, 0x5678, own_tile, REP, 6 /* 64 */, 1, true);
        auto rmsg = reinterpret_cast<const m3::TCU::Message *>(buffer);
        ASSERT_EQ(kernel::TCU::reply_aligned(REP, words + 1, sizeof(uint64_t), buf1, rmsg),
                  Errors::MSG_UNALIGNED);
    }

    logln("SEND+ACK+REPLY with invalid reply EPs"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, TOTAL_EPS);
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 6 /* 64 */, 1);
        ASSERT_EQ(kernel::TCU::send(SEP, empty_msg, 0x1111, REP), Errors::RECV_INV_RPL_EPS);
        auto rmsg = reinterpret_cast<const m3::TCU::Message *>(buffer);
        ASSERT_EQ(kernel::TCU::ack_msg(REP, buf1, rmsg), Errors::RECV_INV_RPL_EPS);
        ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::RECV_INV_RPL_EPS);
    }

    logln("SEND+REPLY with invalid credit EP"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP);
        // install reply EP
        kernel::TCU::config_send(RPLEP, 0x5678, own_tile, REP, 6 /* 64 */, 1, true, TOTAL_EPS);
        // now try to reply with invalid credit EP
        auto rmsg = reinterpret_cast<const m3::TCU::Message *>(buffer);
        ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::SEND_INV_CRD_EP);
    }

    logln("SEND with invalid message size"_cf);
    {
        MsgBuf large_msg;
        large_msg.cast<uint64_t[6]>();
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 12 /* 4096 */, 1);
        ASSERT_EQ(kernel::TCU::send(SEP, large_msg, 0x1111, TCU::NO_REPLIES),
                  Errors::SEND_INV_MSG_SZ);
    }

    logln("REPLY with invalid message size in reply EP"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP);
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 6 /* 64 */, 1);
        // install reply EP
        kernel::TCU::config_send(RPLEP, 0x5678, own_tile, REP, 12 /* 4096 */, 1, true, 2);
        // now try to reply
        auto rmsg = reinterpret_cast<const m3::TCU::Message *>(buffer);
        ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::SEND_INV_MSG_SZ);
    }

    logln("Send EP should not lose credits on failed SENDs"_cf);
    {
        kernel::TCU::config_invalid(REP);
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 6 /* 64 */, 1);
        // try send to invalid receive EP
        ASSERT_EQ(kernel::TCU::send(SEP, empty_msg, 0x1111, TCU::NO_REPLIES), Errors::RECV_GONE);
        // now we should still have credits
        ASSERT_EQ(kernel::TCU::credits(SEP), 1);
    }

    logln("Receive EP should not change on failed REPLYs"_cf);
    {
        kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP, 0x1, 0x1);
        kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 6 /* 64 */, 1);
        // install reply EP
        kernel::TCU::config_send(RPLEP, 0x5678, own_tile, REP2, 6 /* 64 */, 1, true, 2);
        kernel::TCU::config_invalid(REP2);
        // now try reply to invalid receive EP
        auto rmsg = reinterpret_cast<const m3::TCU::Message *>(buffer);
        ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::RECV_GONE);

        // now we should still have credits and the msg should still be unread
        ASSERT_EQ(kernel::TCU::credits(RPLEP), 1);
        uint32_t unread, occupied;
        kernel::TCU::recv_masks(REP, &unread, &occupied);
        ASSERT_EQ(unread, 0x1);
        ASSERT_EQ(occupied, 0x1);
    }
}

static void test_msg_send_empty() {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("SEND with empty message"_cf);

    char buffer[2 * 64];
    uintptr_t buf1 = reinterpret_cast<uintptr_t>(&buffer);

    MsgBuf empty_msg;

    kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP);
    kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 5 /* 32 */, 1);

    // send empty message
    ASSERT_EQ(kernel::TCU::send(SEP, empty_msg, 0x2222, TCU::NO_REPLIES), Errors::SUCCESS);
    ASSERT_EQ(kernel::TCU::max_credits(SEP), 1);
    ASSERT_EQ(kernel::TCU::credits(SEP), 0);

    // fetch message
    const TCU::Message *rmsg;
    while((rmsg = kernel::TCU::fetch_msg(REP, buf1)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x5678);
    ASSERT_EQ(rmsg->replylabel, 0x2222);
    ASSERT_EQ(rmsg->length, 0);
    ASSERT_EQ(rmsg->senderEp, SEP);
    ASSERT_EQ(rmsg->replySize, 5 /* log2(TCU::Message::Header) */);
    ASSERT_EQ(rmsg->replyEp, TCU::INVALID_EP);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, 0);

    ASSERT_EQ(kernel::TCU::ack_msg(REP, buf1, rmsg), Errors::SUCCESS);
}

static void test_msg_reply_empty() {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("REPLY with empty message"_cf);

    char buffer[2 * 64];
    char buffer2[2 * 64];
    uintptr_t buf1 = reinterpret_cast<uintptr_t>(&buffer);
    uintptr_t buf2 = reinterpret_cast<uintptr_t>(&buffer2);

    MsgBuf empty_msg;

    kernel::TCU::config_recv(REP, buf1, 6 /* 64 */, 6 /* 64 */, RPLEP);
    kernel::TCU::config_recv(REP2, buf2, 6 /* 64 */, 6 /* 64 */, TCU::NO_REPLIES);
    kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, 5 /* 32 */, 1);

    // send empty message
    ASSERT_EQ(kernel::TCU::max_credits(SEP), 1);
    ASSERT_EQ(kernel::TCU::credits(SEP), 1);
    ASSERT_EQ(kernel::TCU::send(SEP, empty_msg, 0x1111, REP2), Errors::SUCCESS);
    ASSERT_EQ(kernel::TCU::max_credits(SEP), 1);
    ASSERT_EQ(kernel::TCU::credits(SEP), 0);

    // fetch message
    const TCU::Message *rmsg;
    while((rmsg = kernel::TCU::fetch_msg(REP, buf1)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1234);
    ASSERT_EQ(rmsg->replylabel, 0x1111);
    ASSERT_EQ(rmsg->length, 0);
    ASSERT_EQ(rmsg->senderEp, SEP);
    ASSERT_EQ(rmsg->replySize, 6);
    ASSERT_EQ(rmsg->replyEp, REP2);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, 0);

    // sending with the use-once send EP is not allowed
    ASSERT_EQ(kernel::TCU::send(RPLEP, empty_msg, 0x1111, TCU::NO_REPLIES), Errors::SEND_REPLY_EP);
    // send empty reply
    ASSERT_EQ(kernel::TCU::reply(REP, empty_msg, buf1, rmsg), Errors::SUCCESS);

    ASSERT_EQ(kernel::TCU::max_credits(SEP), 1);
    ASSERT_EQ(kernel::TCU::credits(SEP), 1);

    // fetch reply
    while((rmsg = kernel::TCU::fetch_msg(REP2, buf2)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1111);
    ASSERT_EQ(rmsg->length, 0);
    ASSERT_EQ(rmsg->senderEp, REP);
    ASSERT_EQ(rmsg->replySize, 0);
    ASSERT_EQ(rmsg->replyEp, SEP);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, TCU::Header::FL_REPLY);
    // free slot
    ASSERT_EQ(kernel::TCU::ack_msg(REP2, buf2, rmsg), Errors::SUCCESS);
}

static void test_msg_no_reply() {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("SEND without reply"_cf);

    char buffer[2 * 64];
    char buffer2[2 * 64];
    uintptr_t buf1 = reinterpret_cast<uintptr_t>(&buffer);
    uintptr_t buf2 = reinterpret_cast<uintptr_t>(&buffer2);

    MsgBuf msg, reply, empty_reply;
    auto &msg_val = msg.cast<uint64_t>() = 5678;
    reply.cast<uint64_t>() = 9123;

    kernel::TCU::config_recv(REP, buf1, 7 /* 128 */, 6 /* 64 */, RPLEP);
    kernel::TCU::config_invalid(RPLEP);
    kernel::TCU::config_recv(REP2, buf2, 6 /* 64 */, 6 /* 64 */, TCU::NO_REPLIES);
    kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, 6 /* 64 */, 2);

    // send with replies disabled
    ASSERT_EQ(kernel::TCU::credits(SEP), 2);
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, TCU::NO_REPLIES), Errors::SUCCESS);
    ASSERT_EQ(kernel::TCU::credits(SEP), 1);

    // fetch message
    const TCU::Message *rmsg;
    while((rmsg = kernel::TCU::fetch_msg(REP, buf1)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1234);
    ASSERT_EQ(rmsg->replylabel, 0x1111);
    ASSERT_EQ(rmsg->length, msg.size());
    ASSERT_EQ(rmsg->senderEp, SEP);
    ASSERT_EQ(rmsg->replySize, 5 /* log2(TCU::Message::Header) */);
    ASSERT_EQ(rmsg->replyEp, TCU::INVALID_EP);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, 0);
    const uint64_t *msg_ctrl = reinterpret_cast<const uint64_t *>(rmsg->data);
    ASSERT_EQ(*msg_ctrl, msg_val);

    // reply with data not allowed
    ASSERT_EQ(kernel::TCU::reply(REP, reply, buf1, rmsg), Errors::NO_SEP);
    // empty reply is not allowed
    ASSERT_EQ(kernel::TCU::reply(REP, empty_reply, buf1, rmsg), Errors::NO_SEP);
    ASSERT_EQ(kernel::TCU::ack_msg(REP, buf1, rmsg), Errors::SUCCESS);
}

static void test_msg_no_credits() {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("SEND without credits"_cf);

    char buffer[2 * 64];
    char buffer2[2 * 64];
    uintptr_t buf1 = reinterpret_cast<uintptr_t>(&buffer);
    uintptr_t buf2 = reinterpret_cast<uintptr_t>(&buffer2);

    MsgBuf msg, reply;
    auto &msg_val = msg.cast<uint64_t>() = 5678;
    auto &reply_val = reply.cast<uint64_t>() = 9123;

    kernel::TCU::config_recv(REP, buf1, 7 /* 128 */, 6 /* 64 */, RPLEP);
    kernel::TCU::config_recv(REP2, buf2, 6 /* 64 */, 6 /* 64 */, TCU::NO_REPLIES);
    kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, 6 /* 64 */, TCU::UNLIM_CREDITS);

    // send without credits
    ASSERT_EQ(kernel::TCU::credits(SEP), TCU::UNLIM_CREDITS);
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, REP2), Errors::SUCCESS);
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, REP2), Errors::SUCCESS);
    // receive buffer full
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, REP2), Errors::RECV_NO_SPACE);
    // no credits lost
    ASSERT_EQ(kernel::TCU::credits(SEP), TCU::UNLIM_CREDITS);

    // fetch message
    const TCU::Message *rmsg;
    while((rmsg = kernel::TCU::fetch_msg(REP, buf1)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1234);
    ASSERT_EQ(rmsg->replylabel, 0x1111);
    ASSERT_EQ(rmsg->length, msg.size());
    ASSERT_EQ(rmsg->senderEp, TCU::INVALID_EP);
    ASSERT_EQ(rmsg->replySize, 6);
    ASSERT_EQ(rmsg->replyEp, REP2);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, 0);
    const uint64_t *msg_ctrl = reinterpret_cast<const uint64_t *>(rmsg->data);
    ASSERT_EQ(*msg_ctrl, msg_val);

    // send empty reply
    ASSERT_EQ(kernel::TCU::reply(REP, reply, buf1, rmsg), Errors::SUCCESS);

    // fetch reply
    while((rmsg = kernel::TCU::fetch_msg(REP2, buf2)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1111);
    ASSERT_EQ(rmsg->length, 8);
    ASSERT_EQ(rmsg->senderEp, REP);
    ASSERT_EQ(rmsg->replySize, 0);
    ASSERT_EQ(rmsg->replyEp, TCU::INVALID_EP);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, TCU::Header::FL_REPLY);
    const uint64_t *reply_ctrl = reinterpret_cast<const uint64_t *>(rmsg->data);
    ASSERT_EQ(*reply_ctrl, reply_val);
    // free slot
    ASSERT_EQ(kernel::TCU::ack_msg(REP2, buf2, rmsg), Errors::SUCCESS);

    // credits are still the same
    ASSERT_EQ(kernel::TCU::credits(SEP), TCU::UNLIM_CREDITS);

    // ack the other message we sent above
    rmsg = kernel::TCU::fetch_msg(REP, buf1);
    ASSERT(rmsg != nullptr);
    ASSERT_EQ(kernel::TCU::ack_msg(REP, buf1, rmsg), Errors::SUCCESS);
}

static void test_msg_2send_2reply() {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("Two SENDs and two REPLYs"_cf);

    char buffer[2 * 64];
    char buffer2[2 * 64];
    uintptr_t buf1 = reinterpret_cast<uintptr_t>(&buffer);
    uintptr_t buf2 = reinterpret_cast<uintptr_t>(&buffer2);

    MsgBuf msg, reply;
    auto &msg_val = msg.cast<uint64_t>() = 5678;
    auto &reply_val = reply.cast<uint64_t>() = 9123;

    kernel::TCU::config_recv(REP, buf1, 7 /* 128 */, 6 /* 64 */, RPLEP);
    kernel::TCU::config_recv(REP2, buf2, 7 /* 128 */, 6 /* 64 */, TCU::NO_REPLIES);
    kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, 6 /* 64 */, 2);

    // send twice
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, REP2), Errors::SUCCESS);
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x2222, REP2), Errors::SUCCESS);
    // we need the reply to get our credits back
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0, REP2), Errors::NO_CREDITS);

    for(int i = 0; i < 2; ++i) {
        // fetch message
        const TCU::Message *rmsg;
        while((rmsg = kernel::TCU::fetch_msg(REP, buf1)) == nullptr)
            ;
        // validate contents
        ASSERT_EQ(rmsg->label, 0x1234);
        ASSERT_EQ(rmsg->replylabel, i == 0 ? 0x1111 : 0x2222);
        ASSERT_EQ(rmsg->length, msg.size());
        ASSERT_EQ(rmsg->senderEp, SEP);
        ASSERT_EQ(rmsg->replySize, 6);
        ASSERT_EQ(rmsg->replyEp, REP2);
        ASSERT_EQ(rmsg->senderTile, own_tile.raw());
        ASSERT_EQ(rmsg->flags, 0);
        const uint64_t *msg_ctrl = reinterpret_cast<const uint64_t *>(rmsg->data);
        ASSERT_EQ(*msg_ctrl, msg_val);

        // message too large
        MsgBuf large_msg;
        large_msg.cast<uint8_t[1 + 64 - sizeof(TCU::Message::Header)]>();
        ASSERT_EQ(kernel::TCU::reply(REP, large_msg, buf1, rmsg), Errors::OUT_OF_BOUNDS);
        // send reply
        ASSERT_EQ(kernel::TCU::reply(REP, reply, buf1, rmsg), Errors::SUCCESS);
        // can't reply again (SEP invalid)
        ASSERT_EQ(kernel::TCU::reply(REP, reply, buf1, rmsg), Errors::NO_SEP);
    }

    for(int i = 0; i < 2; ++i) {
        // fetch reply
        const TCU::Message *rmsg;
        while((rmsg = kernel::TCU::fetch_msg(REP2, buf2)) == nullptr)
            ;
        // validate contents
        ASSERT_EQ(rmsg->label, i == 0 ? 0x1111 : 0x2222);
        ASSERT_EQ(rmsg->length, reply.size());
        ASSERT_EQ(rmsg->senderEp, REP);
        ASSERT_EQ(rmsg->replySize, 0);
        ASSERT_EQ(rmsg->replyEp, SEP);
        ASSERT_EQ(rmsg->senderTile, own_tile.raw());
        ASSERT_EQ(rmsg->flags, TCU::Header::FL_REPLY);
        const uint64_t *msg_ctrl = reinterpret_cast<const uint64_t *>(rmsg->data);
        ASSERT_EQ(*msg_ctrl, reply_val);
        // free slot
        ASSERT_EQ(kernel::TCU::ack_msg(REP2, buf2, rmsg), Errors::SUCCESS);
    }

    // credits are back
    ASSERT_EQ(kernel::TCU::credits(SEP), 2);
}

template<typename DATA>
static void test_msg(size_t msg_size_in, size_t reply_size_in) {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("SEND+REPLY with {} {}B words"_cf, msg_size_in, sizeof(DATA));

    const size_t TOTAL_MSG_SIZE = msg_size_in * sizeof(DATA) + sizeof(TCU::Header);
    const size_t TOTAL_REPLY_SIZE = reply_size_in * sizeof(DATA) + sizeof(TCU::Header);

    char rbuffer[2 * TOTAL_MSG_SIZE];
    char rbuffer2[2 * TOTAL_REPLY_SIZE];
    uintptr_t buf1 = reinterpret_cast<uintptr_t>(&rbuffer);
    uintptr_t buf2 = reinterpret_cast<uintptr_t>(&rbuffer2);

    // prepare test data
    MsgBuf msg, reply;
    auto *msg_data = &msg.cast<DATA>();
    auto *reply_data = &reply.cast<DATA>();
    for(size_t i = 0; i < msg_size_in; ++i)
        msg_data[i] = i + 1;
    msg.set_size(msg_size_in * sizeof(DATA));
    for(size_t i = 0; i < reply_size_in; ++i)
        reply_data[i] = reply_size_in - i;
    reply.set_size(reply_size_in * sizeof(DATA));

    TCU::reg_t slot_msgsize = m3::getnextlog2(TOTAL_MSG_SIZE);
    TCU::reg_t slot_replysize = m3::getnextlog2(TOTAL_REPLY_SIZE);

    kernel::TCU::config_recv(REP, buf1, slot_msgsize + 1, slot_msgsize, RPLEP);
    kernel::TCU::config_recv(REP2, buf2, slot_replysize + 1, slot_replysize, TCU::NO_REPLIES);
    kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, slot_msgsize, 1);

    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, REP2), Errors::SUCCESS);

    // fetch message
    const TCU::Message *rmsg;
    while((rmsg = kernel::TCU::fetch_msg(REP, buf1)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1234);
    ASSERT_EQ(rmsg->replylabel, 0x1111);
    ASSERT_EQ(rmsg->length, msg.size());
    ASSERT_EQ(rmsg->senderEp, SEP);
    ASSERT_EQ(rmsg->replyEp, REP2);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, 0);
    const DATA *msg_ctrl = reinterpret_cast<const DATA *>(rmsg->data);
    for(size_t i = 0; i < msg_size_in; ++i)
        ASSERT_EQ(msg_ctrl[i], msg_data[i]);

    // we need the reply to get our credits back
    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0, REP2), Errors::NO_CREDITS);

    // send reply
    ASSERT_EQ(kernel::TCU::reply(REP, reply, buf1, rmsg), Errors::SUCCESS);

    // fetch reply
    while((rmsg = kernel::TCU::fetch_msg(REP2, buf2)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1111);
    ASSERT_EQ(rmsg->length, reply.size());
    ASSERT_EQ(rmsg->senderEp, REP);
    ASSERT_EQ(rmsg->replyEp, SEP);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, TCU::Header::FL_REPLY);
    msg_ctrl = reinterpret_cast<const DATA *>(rmsg->data);
    for(size_t i = 0; i < reply_size_in; ++i)
        ASSERT_EQ(msg_ctrl[i], reply_data[i]);
    // free slot
    ASSERT_EQ(kernel::TCU::ack_msg(REP2, buf2, rmsg), Errors::SUCCESS);
}

static void test_msg_receive() {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("SEND+FETCH and verify unread/occupied/rpos/wpos"_cf);

    char rbuffer[32 * 32];
    uintptr_t buf = reinterpret_cast<uintptr_t>(&rbuffer);

    kernel::TCU::config_recv(REP, buf, 5 + 5 /* 32 * 32 */, 5 /* 32 */, TCU::NO_REPLIES, 0, 0);
    kernel::TCU::config_send(SEP, 0x5678, own_tile, REP, 5 /* 32 */, TCU::UNLIM_CREDITS);

    uint8_t expected_rpos = 0, expected_wpos = 0;
    uint32_t expected_unread = 0, expected_occupied = 0;
    for(int j = 0; j < 32; ++j) {
        MsgBuf msg;
        msg.cast<uint64_t>() = 0xDEAD'BEEF;

        // send all messages
        for(int i = 0; i < j; ++i) {
            uint8_t rpos, wpos;
            uint32_t unread, occupied;
            kernel::TCU::recv_pos(REP, &rpos, &wpos);
            kernel::TCU::recv_masks(REP, &unread, &occupied);
            ASSERT_EQ(rpos, expected_rpos);
            ASSERT_EQ(wpos, expected_wpos);
            ASSERT_EQ(unread, expected_unread);
            ASSERT_EQ(occupied, expected_occupied);

            ASSERT_EQ(kernel::TCU::send(SEP, msg, static_cast<label_t>(i + 1), TCU::NO_REPLIES),
                      Errors::SUCCESS);
            if(wpos == 32) {
                expected_unread |= 1 << 0;
                expected_occupied |= 1 << 0;
            }
            else {
                expected_unread |= 1 << wpos;
                expected_occupied |= 1 << wpos;
            }

            if(expected_wpos == 32)
                expected_wpos = 1;
            else
                expected_wpos++;
        }

        // fetch all messages
        for(int i = 0; i < j; ++i) {
            uint8_t rpos, wpos;
            uint32_t unread, occupied;
            kernel::TCU::recv_pos(REP, &rpos, &wpos);
            kernel::TCU::recv_masks(REP, &unread, &occupied);
            ASSERT_EQ(rpos, expected_rpos);
            ASSERT_EQ(wpos, expected_wpos);
            ASSERT_EQ(unread, expected_unread);
            ASSERT_EQ(occupied, expected_occupied);

            const TCU::Message *rmsg = kernel::TCU::fetch_msg(REP, buf);
            ASSERT(rmsg != nullptr);

            if(rpos == 32)
                expected_unread &= ~(1U << 0);
            else
                expected_unread &= ~(1U << rpos);

            if(expected_rpos == 32)
                expected_rpos = 1;
            else
                expected_rpos++;

            kernel::TCU::recv_masks(REP, &unread, &occupied);
            ASSERT_EQ(unread, expected_unread);
            ASSERT_EQ(occupied, expected_occupied);

            // validate contents
            ASSERT_EQ(rmsg->label, 0x5678);
            ASSERT_EQ(rmsg->replylabel, static_cast<uint32_t>(i + 1));

            // free slot
            ASSERT_EQ(kernel::TCU::ack_msg(REP, buf, rmsg), Errors::SUCCESS);

            if(rpos == 32)
                expected_occupied &= ~(1U << 0);
            else
                expected_occupied &= ~(1U << rpos);
        }
    }
}

static void test_unaligned_recvbuf(size_t pad, size_t msg_size_in) {
    auto own_tile = TileId::from_raw(env()->tile_id);

    logln("SEND {}B with {}B padding of recv-buf"_cf, msg_size_in, pad);

    const size_t TOTAL_MSG_SIZE = msg_size_in + sizeof(TCU::Header);
    char rbuffer[TOTAL_MSG_SIZE + 32]; // reserve some extra space for padding
    uintptr_t recv_buf = reinterpret_cast<uintptr_t>(&rbuffer) + pad;

    // prepare test data
    MsgBuf msg;
    auto *msg_data = &msg.cast<uint8_t>();
    for(size_t i = 0; i < msg_size_in; ++i)
        msg_data[i] = i + 1;
    msg.set_size(msg_size_in);

    // mark end of recv-buf, this value should not be overwritten
    rbuffer[sizeof(TCU::Header) + msg_size_in + pad] = 0xFF;

    TCU::reg_t slot_msgsize = m3::getnextlog2(TOTAL_MSG_SIZE);

    kernel::TCU::config_recv(REP, recv_buf, slot_msgsize + 1, slot_msgsize, TCU::NO_REPLIES);
    kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, slot_msgsize, 1);

    ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x1111, TCU::INVALID_EP), Errors::SUCCESS);

    // fetch message
    const TCU::Message *rmsg;
    while((rmsg = kernel::TCU::fetch_msg(REP, recv_buf)) == nullptr)
        ;
    // validate contents
    ASSERT_EQ(rmsg->label, 0x1234);
    ASSERT_EQ(rmsg->replylabel, 0x1111);
    ASSERT_EQ(rmsg->length, msg.size());
    ASSERT_EQ(rmsg->senderEp, SEP);
    ASSERT_EQ(rmsg->replyEp, TCU::INVALID_EP);
    ASSERT_EQ(rmsg->senderTile, own_tile.raw());
    ASSERT_EQ(rmsg->flags, 0);
    const uint8_t *msg_ctrl = reinterpret_cast<const uint8_t *>(rmsg->data);
    for(size_t i = 0; i < msg_size_in; ++i)
        ASSERT_EQ(msg_ctrl[i], msg_data[i]);
    ASSERT_EQ(msg_ctrl[msg_size_in], 0xFF);

    // free slot
    ASSERT_EQ(kernel::TCU::ack_msg(REP, recv_buf, rmsg), Errors::SUCCESS);
}

void test_msgs() {
    test_msg_receive();
    test_msg_errors();
    test_msg_send_empty();
    test_msg_reply_empty();
    test_msg_no_reply();
    test_msg_no_credits();
    test_msg_2send_2reply();

    // test different lengths
    for(size_t i = 1; i <= 80; i++) {
        test_msg<uint8_t>(i, i);
        test_msg<uint16_t>(i, i);
        test_msg<uint32_t>(i, i);
        test_msg<uint64_t>(i, i);
    }

    // test different alignments of receive buffer
    for(size_t pad = 1; pad <= 16; pad++) {
        for(size_t n_bytes = 1; n_bytes <= 128; n_bytes++) {
            test_unaligned_recvbuf(pad, n_bytes);
        }
    }
}
