/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

namespace m3 {

class EnvVars {
    EnvVars() = delete;

public:
    /**
     * @return the number of environment variables
     */
    static size_t count();

    /**
     * @return the array of all environment variables (not null-terminated!)
     */
    static const char *const *vars();

    /**
     * @param key the key of the variable
     * @return the value of the environment variable with given key
     */
    static const char *get(const char *key);

    /**
     * Sets the value of the environment variable with given key.
     *
     * @param key the key of the variable (must not contain a '=')
     * @param value the new value
     */
    static void set(const char *key, const char *value);

    /**
     * Removes the environment variable with given key.
     *
     * @param key the key of the variable (must not contain a '=')
     */
    static void remove(const char *key);

private:
    static void copy();
    static void append(char *pair);
    static char **find_var(const char *key, size_t key_len);
};

}
