/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/stream/IStringStream.h>
#include <base/time/Instant.h>

#include <m3/accel/StreamAccel.h>
#include <m3/pipe/IndirectPipe.h>
#include <m3/session/VTerm.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/Dir.h>
#include <m3/vfs/VFS.h>
#include <m3/Syscalls.h>
#include <m3/tiles/Tile.h>
#include <m3/tiles/ChildActivity.h>

#include <memory>
#include <stdlib.h>

#include "Args.h"
#include "Builtin.h"
#include "Input.h"
#include "Parser.h"
#include "Vars.h"

using namespace m3;

static const CycleDuration ACOMP_TIME = CycleDuration::from_raw(4096);

static const size_t PIPE_SHM_SIZE   = 512 * 1024;

static const uint MIN_EPS = 16;
static const uint64_t MIN_TIME = 100000; // 100µs
static const size_t MIN_PTS = 16;

static bool have_vterm = false;
static VTerm *vterm;

static char **build_args(Command *cmd) {
    char **res = new char*[cmd->args->count + 1];
    for(size_t i = 0; i < cmd->args->count; ++i)
        res[i] = (char*)expr_value(cmd->args->args[i]);
    res[cmd->args->count] = nullptr;
    return res;
}

static const char *get_pe_name(const VarList &vars, const char *path) {
    FStream f(path, FILE_R | FILE_X);
    if(f.bad())
        return "";

    // accelerator description file?
    if(f.read() == '@' && f.read() == '=') {
        static char line[128];
        f.getline(line, sizeof(line));
        return line;
    }

    for(size_t i = 0; i < vars.count; ++i) {
        if(strcmp(vars.vars[i].name, "TILE") == 0)
            return expr_value(vars.vars[i].value);
    }
    // prefer a different tile to prevent that we run out of EPs or similar
    return "core|own";
}

static void execute_assignment(CmdList *list) {
    Command *cmd = list->cmds[0];

    for(size_t i = 0; i < cmd->vars->count; ++i) {
        Var *v = cmd->vars->vars + i;
        Vars::get().set(v->name, expr_value(v->value));
    }
}

static void execute_pipeline(Pipes &pipesrv, CmdList *list) {
    bool builtin[MAX_CMDS];
    std::unique_ptr<IndirectPipe> pipes[MAX_CMDS] = {nullptr};
    std::unique_ptr<MemGate> mems[MAX_CMDS] = {nullptr};
    // destroy the activities first to prevent errors due to destroyed communication channels
    std::unique_ptr<StreamAccel> accels[MAX_CMDS] = {nullptr};
    Reference<Tile> tiles[MAX_CMDS];
    std::unique_ptr<ChildActivity> acts[MAX_CMDS] = {nullptr};

    // get tile types
    for(size_t i = 0; i < list->count; ++i) {
        if(list->cmds[i]->args->count == 0) {
            errmsg("Command has no arguments");
            return;
        }

        const char *cmd_name = expr_value(list->cmds[i]->args->args[0]);
        builtin[i] = Builtin::is_builtin(cmd_name);
        if(i > 0 && builtin[i]) {
            errmsg("Builtin command cannot read from pipe");
            return;
        }
        if(!builtin[i]) {
            const char *tile_name = get_pe_name(*list->cmds[i]->vars, cmd_name);
            tiles[i] = Tile::get(tile_name);
        }
    }

    size_t act_count = 0;
    FileRef<File> infile;
    FileRef<File> outfile;
    FileRef<File> errfile;
    for(size_t i = 0; i < list->count; ++i) {
        Command *cmd = list->cmds[i];

        if(!builtin[i]) {
            // if we share our tile with this child activity, give it separate quotas to ensure that we get our
            // share (we don't trust the child apps)
            if(tiles[i]->sel() == Activity::own().tile()->sel()) {
                Quota<uint> eps;
                Quota<uint64_t> time;
                Quota<size_t> pts;
                tiles[i]->quota(&eps, &time, &pts);
                if(eps.left > MIN_EPS && pts.left > MIN_PTS)
                    tiles[i] = tiles[i]->derive(eps.left - MIN_EPS, time.total - MIN_TIME, pts.left - MIN_PTS);
                else
                    tiles[i] = Tile::get("core");
            }

            acts[i] = std::make_unique<ChildActivity>(tiles[i], expr_value(cmd->args->args[0]));
            act_count++;
        }

        // I/O redirection is only supported at the beginning and end
        if((i + 1 < list->count && cmd->redirs->fds[STDOUT_FD]) ||
            (i > 0 && cmd->redirs->fds[STDIN_FD])) {
            throw MessageException("Invalid I/O redirection");
        }

        fd_t infd = STDIN_FD;
        if(i == 0) {
            if(cmd->redirs->fds[STDIN_FD])
                infile = VFS::open(cmd->redirs->fds[STDIN_FD], FILE_R | FILE_NEWSESS);
            else if(vterm)
                infile = vterm->create_channel(true);
            if(infile.is_valid())
                infd = infile->fd();
        }
        else if((builtin[i - 1] || tiles[i - 1]->desc().is_programmable()) ||
                (builtin[i] || tiles[i]->desc().is_programmable()))
            infd = pipes[i - 1]->reader().fd();

        if(acts[i] && infd != STDIN_FD)
            acts[i]->add_file(STDIN_FD, infd);

        fd_t outfd = STDOUT_FD;
        if(i + 1 == list->count) {
            if(cmd->redirs->fds[STDOUT_FD])
                outfile = VFS::open(cmd->redirs->fds[STDOUT_FD], FILE_W | FILE_CREATE | FILE_TRUNC | FILE_NEWSESS);
            else if(vterm)
                outfile = vterm->create_channel(false);
            if(outfile.is_valid())
                outfd = outfile->fd();
        }
        else if((builtin[i] || tiles[i]->desc().is_programmable()) ||
                (builtin[i + 1] || tiles[i + 1]->desc().is_programmable())) {
            mems[i] = std::make_unique<MemGate>(MemGate::create_global(PIPE_SHM_SIZE, MemGate::RW));
            pipes[i] = std::make_unique<IndirectPipe>(pipesrv, *mems[i], PIPE_SHM_SIZE);
            outfd = pipes[i]->writer().fd();
        }

        if(acts[i] && outfd != STDOUT_FD)
            acts[i]->add_file(STDOUT_FD, outfd);

        char **args = build_args(cmd);

        if(builtin[i]) {
            Builtin::execute(args, outfd);
            // close stdout pipe to send EOF
            if(pipes[i])
                pipes[i]->close_writer();
        }
        else if(tiles[i]->desc().is_programmable()) {
            if(vterm)
                errfile = vterm->create_channel(false);
            if(errfile.is_valid())
                acts[i]->add_file(STDERR_FD, errfile->fd());

            acts[i]->add_mount("/", "/");

            acts[i]->exec(static_cast<int>(cmd->args->count), const_cast<const char**>(args));
        }
        else
            accels[i] = std::make_unique<StreamAccel>(acts[i], ACOMP_TIME);

        delete[] args;

        if(i > 0 && pipes[i - 1]) {
            if(acts[i] && acts[i]->tile_desc().is_programmable())
                pipes[i - 1]->close_reader();
            if(acts[i - 1] && acts[i - 1]->tile_desc().is_programmable())
                pipes[i - 1]->close_writer();
        }
    }

    // connect input/output of accelerators
    if(act_count > 0) {
        FileRef<File> clones[act_count * 2];
        size_t c = 0;
        for(size_t i = 0; i < act_count; ++i) {
            if(accels[i]) {
                fd_t our_in_fd = acts[i]->get_file(STDIN_FD);
                if(our_in_fd != FileTable::MAX_FDS) {
                    auto our_in = Activity::own().files()->get(our_in_fd);
                    auto ain = our_in->clone();
                    accels[i]->connect_input(static_cast<GenericFile*>(&*ain));
                    clones[c++] = std::move(ain);
                }
                else if(accels[i - 1])
                    accels[i]->connect_input(accels[i - 1].get());

                fd_t our_out_fd = acts[i]->get_file(STDOUT_FD);
                if(our_out_fd != FileTable::MAX_FDS) {
                    auto our_out = Activity::own().files()->get(our_out_fd);
                    auto aout = our_out->clone();
                    accels[i]->connect_output(static_cast<GenericFile*>(&*aout));
                    clones[c++] = std::move(aout);
                }
                else if(accels[i + 1])
                    accels[i]->connect_output(accels[i + 1].get());
            }
        }

        // start accelerator activities
        for(size_t i = 0; i < act_count; ++i) {
            if(accels[i])
                acts[i]->start();
        }

        for(size_t rem = act_count; rem > 0; ) {
            capsel_t sels[act_count];
            for(size_t x = 0, i = 0; i < act_count; ++i) {
                if(acts[i])
                    sels[x++] = acts[i]->sel();
            }

            Syscalls::activity_wait(sels, rem, 1, nullptr);

            bool signal = false;
            capsel_t act = KIF::INV_SEL;
            int exitcode = 0;
            if(have_vterm) {
                // fetch the signal first to ensure we don't have one from last time
                cin.file()->fetch_signal();
            }

            while(true) {
                const TCU::Message *msg;
                if((msg = RecvGate::upcall().fetch())) {
                    GateIStream is(RecvGate::upcall(), msg);
                    auto upcall = reinterpret_cast<const KIF::Upcall::ActivityWait*>(msg->data);
                    act = upcall->act_sel;
                    exitcode = upcall->exitcode;
                    reply_vmsg(is, 0);
                    break;
                }
                else if(have_vterm && cin.file()->fetch_signal()) {
                    signal = true;
                    Syscalls::activity_wait(sels, 0, 1, nullptr);
                    break;
                }

                Activity::sleep();
            }

            for(size_t i = 0; i < act_count; ++i) {
                if(acts[i] && (signal || acts[i]->sel() == act)) {
                    if(exitcode != 0) {
                        cerr << expr_value(list->cmds[i]->args->args[0])
                             << " terminated with exit code " << exitcode << "\n";
                    }
                    else if(signal) {
                        cerr << expr_value(list->cmds[i]->args->args[0])
                             << " terminated by signal\n";
                    }
                    if(!acts[i]->tile_desc().is_programmable()) {
                        if(pipes[i])
                            pipes[i]->close_writer();
                        if(i > 0 && pipes[i - 1])
                            pipes[i - 1]->close_reader();
                    }
                    delete acts[i].release();
                    acts[i] = nullptr;
                    rem--;
                }
            }
        }
    }
}

static void execute(Pipes &pipesrv, CmdList *list) {
    for(size_t i = 0; i < list->count; ++i) {
        Args::prefix_path(list->cmds[i]->args);
        Args::expand(list->cmds[i]->args);
    }

    try {
        if(list->count == 1 && list->cmds[0]->args->count == 0)
            execute_assignment(list);
        else
            execute_pipeline(pipesrv, list);
    }
    catch(const Exception &e) {
        errmsg("command failed: " << e.what());
    }
}

size_t prompt_len() {
    return strlen(VFS::cwd()) + 3;
}

void print_prompt() {
    cout << VFS::cwd() << " $ ";
}

int main(int argc, char **argv) {
    Pipes pipesrv("pipes");

    try {
        vterm = new VTerm("vterm");

        // change stdin, stdout, and stderr to vterm
        const fd_t fds[] = {STDIN_FD, STDOUT_FD, STDERR_FD};
        for(fd_t fd : fds)
            Activity::own().files()->set(fd, vterm->create_channel(fd == STDIN_FD));
        have_vterm = true;
    }
    catch(const Exception &e) {
        errmsg("Unable to open vterm: " << e.what());
    }

    VFS::set_cwd("/");

    if(argc > 1) {
        OStringStream os;
        for(int i = 1; i < argc; ++i)
            os << argv[i] << " ";

        CmdList *list = parse_command(os.str());
        if(!list)
            exitmsg("Unable to parse command '" << os.str() << "'");

        auto start = TimeInstant::now();
        execute(pipesrv, list);
        auto end = TimeInstant::now();
        ast_cmds_destroy(list);

        cerr << "Execution took " << end.duration_since(start) << "\n";
        return 0;
    }

    cout << "========================\n";
    cout << "Welcome to the M3 shell!\n";
    cout << "========================\n";
    cout << "\n";

    char buffer[256];
    while(!cin.eof()) {
        print_prompt();
        cout.flush();

        if(have_vterm)
            cin.file()->set_tmode(GenericFile::TMode::RAW);
        ssize_t len = Input::readline(buffer, sizeof(buffer));
        if(have_vterm)
            cin.file()->set_tmode(GenericFile::TMode::COOKED);
        if(len < 0)
            break;

        CmdList *list = parse_command(buffer);
        if(!list)
            continue;

        execute(pipesrv, list);
        ast_cmds_destroy(list);
    }
    return 0;
}
