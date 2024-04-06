#pragma once

#include <node_api.h>
#include "utils.h"

class WireguardConstructorReference {
private:
  static WireguardConstructorReference *instance_;
  napi_ref wireguard_constructor_ref_ = nullptr;

  WireguardConstructorReference() {}

public:
  static WireguardConstructorReference *GetInstance();

  napi_ref SetReference(napi_env env, napi_value wireguard_tunnel_class);

  [[maybe_unused]] napi_ref GetReference();

  napi_value GetClass(napi_env env);
};