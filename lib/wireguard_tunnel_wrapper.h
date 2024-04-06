#pragma once

#include <node_api.h>
#include <iostream>
#include <cstring>
#include "wireguard_tunnel.h"
#include "utils.h"
#include "reference_singleton.h"

napi_value WireguardTunnelConstructor(napi_env env, napi_callback_info info);

napi_value WireguardTunnelGetPrivateKey(napi_env env, napi_callback_info info);

napi_value WireguardTunnelReadWrite(napi_env env, napi_callback_info info, WG_OP_TYPE op_type);

napi_value WireguardTunnelRead(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrite(napi_env env, napi_callback_info info);

napi_value WireguardTunnelGetPublicKey(napi_env env, napi_callback_info info);
