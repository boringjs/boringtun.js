#include "reference_singleton.h"

WireguardConstructorReference *WireguardConstructorReference::instance_ = nullptr;

WireguardConstructorReference *WireguardConstructorReference::GetInstance() {
  if (instance_ == nullptr) {
    instance_ = new WireguardConstructorReference();
  }
  return instance_;
}

napi_ref WireguardConstructorReference::SetReference(napi_env env, napi_value wireguard_tunnel_class) {
  // Why i cannot save wireguard_tunnel_class
  ASSERT_STATUS(napi_create_reference(env, wireguard_tunnel_class, 1, &wireguard_constructor_ref_),
                "Cannot assert constructor to class");

  return wireguard_constructor_ref_;
}

napi_ref WireguardConstructorReference::GetReference() {
  return wireguard_constructor_ref_;
}

napi_value WireguardConstructorReference::GetClass(napi_env env) {
  napi_value wireguard_constructor = nullptr;
  ASSERT_STATUS(napi_get_reference_value(env, wireguard_constructor_ref_, &wireguard_constructor),
                "Cannot get reference of constructor");

  return wireguard_constructor;
}
