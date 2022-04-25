/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

#include <m3/stream/FStream.h>
#include <m3/stream/Standard.h>

#include "Parser.h"
#include "parser.tab.h"

using namespace m3;

static bool eof = false;
static const char *line;
static size_t line_pos;
CmdList *curcmd;
extern YYSTYPE yylval;

EXTERN_C int yyparse(void);

EXTERN_C void yyerror(char const *s) {
    cerr << s << "\n";
    cerr.flush();
}

EXTERN_C int yylex() {
    size_t start = line_pos;
    size_t end = 0;

    char c;
    if(!eof) {
        bool in_str = false;
        while((c = line[line_pos]) != '\0') {
            if(in_str) {
                line_pos++;
                if(c == '"') {
                    end = line_pos - 1;
                    in_str = false;
                    break;
                }
                continue;
            }

            if(c == '"') {
                if(line_pos != start)
                    break;
                start = line_pos + 1;
                in_str = true;
            }
            else if(c == '|' || c == ';' || c == '>' || c == '<'  || c == '=' || c == '$') {
                if(line_pos == start) {
                    line_pos++;
                    return c;
                }
                break;
            }

            if(c == '\n') {
                eof = true;
                break;
            }
            if(c == ' ' || c == '\t') {
                if(line_pos > start)
                    break;
                start++;
            }
            line_pos++;
        }
    }

    if(line_pos > start) {
        end = end ? end : line_pos;
        char *token = static_cast<char*>(malloc(end - start + 1));
        strncpy(token, line + start, end - start);
        token[end - start] = '\0';
        yylval.str = token;
        return T_STRING;
    }
    return -1;
}

Expr *ast_expr_create(const char *name, int is_var) {
    Expr *e = new Expr;
    e->is_var = is_var;
    e->name_val = name;
    return e;
}

void ast_expr_destroy(Expr *e) {
    free(const_cast<char*>(e->name_val));
    delete e;
}

Command *ast_cmd_create(VarList *vars, ArgList *args, RedirList *redirs) {
    Command *cmd = new Command;
    cmd->vars = vars;
    cmd->args = args;
    cmd->redirs = redirs;
    return cmd;
}

void ast_cmd_destroy(Command *cmd) {
    if(cmd) {
        ast_vars_destroy(cmd->vars);
        ast_redirs_destroy(cmd->redirs);
        ast_args_destroy(cmd->args);
        delete cmd;
    }
}

CmdList *ast_cmds_create() {
    CmdList *list = new CmdList;
    list->count = 0;
    return list;
}

void ast_cmds_append(CmdList *list, Command *cmd) {
    if(list->count == MAX_CMDS)
        return;

    list->cmds[list->count++] = cmd;
}

void ast_cmds_destroy(CmdList *list) {
    if(list) {
        for(size_t i = 0; i < list->count; ++i)
            ast_cmd_destroy(list->cmds[i]);
        delete list;
    }
}

RedirList *ast_redirs_create(void) {
    RedirList *list = new RedirList;
    list->fds[STDIN_FD] = nullptr;
    list->fds[STDOUT_FD] = nullptr;
    return list;
}

void ast_redirs_set(RedirList *list, int fd, const char *file) {
    assert(fd == STDIN_FD || fd == STDOUT_FD);
    if(list->fds[fd])
        free(const_cast<char*>(list->fds[fd]));
    list->fds[fd] = file;
}

void ast_redirs_destroy(RedirList *list) {
    free(const_cast<char*>(list->fds[STDIN_FD]));
    free(const_cast<char*>(list->fds[STDOUT_FD]));
    delete list;
}

ArgList *ast_args_create() {
    ArgList *list = new ArgList;
    list->count = 0;
    return list;
}

void ast_args_append(ArgList *list, Expr *arg) {
    if(list->count == MAX_ARGS)
        return;

    list->args[list->count++] = arg;
}

void ast_args_destroy(ArgList *list) {
    if(list) {
        for(size_t i = 0; i < list->count; ++i)
            ast_expr_destroy(list->args[i]);
        delete list;
    }
}

VarList *ast_vars_create(void) {
    VarList *list = new VarList;
    list->count = 0;
    return list;
}

void ast_vars_set(VarList *list, const char *name, Expr *value) {
    if(list->count == MAX_VARS)
        return;

    list->vars[list->count].name = name;
    list->vars[list->count].value = value;
    list->count++;
}

void ast_vars_destroy(VarList *list) {
    for(size_t i = 0; i < list->count; ++i) {
        free(const_cast<char*>(list->vars[i].name));
        ast_expr_destroy(list->vars[i].value);
    }
    delete list;
}

CmdList *parse_command(const char *_line) {
    eof = false;
    curcmd = nullptr;
    line = _line;
    line_pos = 0;
    yyparse();
    return curcmd;
}
