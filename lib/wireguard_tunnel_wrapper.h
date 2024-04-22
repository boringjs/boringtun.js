#pragma once

#include <node_api.h>
#include <cstring>
#include "wireguard_tunnel.h"
#include "reference_singleton.h"

enum WG_OP_TYPE {
  UNKNOWN = 0,
  READ = 1,
  WRITE = 2,
  TICK = 3,
  FORCE_HANDSHAKE = 4,
};

napi_value WireguardTunnelWrapperConstructor(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperGetPrivateKey(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperHandler(napi_env env, napi_callback_info info, WG_OP_TYPE op_type);

napi_value WireguardTunnelWrapperRead(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperTick(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperForceHandshake(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperWrite(napi_env env, napi_callback_info info);

napi_value WireguardTunnelWrapperGetPublicKey(napi_env env, napi_callback_info info);

void CreateStringConstants(napi_env &env, napi_value &exports, const char *str);

napi_status RegisterWireguardTunnel(napi_env env, napi_value exports);
