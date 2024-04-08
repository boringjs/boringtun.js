#pragma once

#include <node_api.h>
#include <iostream>
#include <cstring>
#include "wireguard_tunnel.h"
#include "utils.h"
#include "reference_singleton.h"

napi_value WireguardTunnelWrapperConstructor(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperGetPrivateKey(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperReadWrite(napi_env env, napi_callback_info info, WG_OP_TYPE op_type);

napi_value WireguardTunnelWrapperRead(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperWrite(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperGetPublicKey(napi_env env, napi_callback_info info);

void CreateStringConstants(napi_env &env, napi_value &exports, const char *str);

napi_status RegisterWireguardTunnel(napi_env env, napi_value exports);
