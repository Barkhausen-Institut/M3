#pragma once

#include <stdexcept>
#include <string>
#include <cstring>
#include <errno.h>

namespace Err {

static inline bool chk(bool retVal, char const *opDescr) {
    if (retVal != false)
        return retVal;
    throw std::runtime_error(opDescr);
}

template <typename T>
static inline T chk(T retVal, char const *opDescr) {
    if (retVal >= 0)
        return retVal;
    throw std::runtime_error(opDescr);
}

template <typename T>
static inline T *chk(T *ptr, char const *opDescr) {
    if (ptr != nullptr)
        return ptr;
    throw std::runtime_error(opDescr);
}

template <typename T>
static inline T *chksys(T *ptr, char const *opDescr) {
    if (ptr != nullptr)
        return ptr;
    throw std::runtime_error(std::string(opDescr) + " (errno=" +
                             std::to_string(errno) + ", " + strerror(errno) + ")");
}

template <typename T>
static inline T chksys(T retVal, char const *opDescr) {
    if (retVal >= 0)
        return retVal;
    throw std::runtime_error(std::string(opDescr) + " (errno=" +
                             std::to_string(errno) + ", " + strerror(errno) + ")");
}

} // namespace Err

