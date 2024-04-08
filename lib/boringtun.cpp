#define NAPI_VERSION 9

#include <node_api.h>
#include "wireguard_tunnel_wrapper.h"
#include "wireguard_global_wrapper.h"

// Initialize the addon
napi_value Init(napi_env env, napi_value exports) {
  if (RegisterGlobalConstants(env, exports) != napi_ok) {
    return nullptr;
  }

  if (RegisterGlobalFunctions(env, exports) != napi_ok) {
    return nullptr;
  }

  if (RegisterWireguardTunnel(env, exports) != napi_ok) {
    return nullptr;
  }

  return exports;
}

// Register the module
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)