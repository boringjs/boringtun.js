#pragma once

#include <node_api.h>
#include <iostream>
#include <cstring>
#include "wireguard_tunnel.h"

extern "C" {
#include "../boringtun/boringtun/src/wireguard_ffi.h"
}
#ifndef BORINGTUNJS_UTILS_H
#define BORINGTUNJS_UTILS_H


#define TO_STRING(env, str, size, result_ptr) if(napi_create_string_utf8(env, str, size, result_ptr) != napi_ok){ \
        napi_throw_error(env, nullptr, "TO_STRING: Failed to convert to result string");  \
        return nullptr; \
    }

#define ASSERT_STATUS(status, msg) \
    if ((status) != napi_ok) { \
        napi_throw_error(env, nullptr, msg); \
        return nullptr; \
    }

#define ASSERT_SILENT(status) \
    if ((status) != napi_ok) {\
        std::cout << "NATIVE ERROR BoringTun: Something wrong with silent assert" << std::endl;  \
        return ; \
    }


enum WG_OP_TYPE {
  READ = 1,
  WRITE = 2,
};


#endif //BORINGTUNJS_UTILS_H
