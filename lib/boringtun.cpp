#define NAPI_VERSION 9

#include <node_api.h>
#include <iostream>
#include "utils.h"
#include "wireguard_tunnel_wrapper.h"
#include "reference_singleton.h"
#include "wireguard_global_wrapper.h"


napi_ref logger_callback_ref = nullptr;
napi_env global_env = nullptr;

napi_value SetLoggingFunction(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_value result;

  ASSERT_STATUS(napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), "Failed to parse arguments");

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Function expects only one arg.");
    return nullptr;
  }

  napi_valuetype val_type_key;
  ASSERT_STATUS(napi_typeof(env, args[0], &val_type_key), "Failing getting args type")

  if (val_type_key != napi_function) {
    napi_throw_type_error(env, nullptr, "Input value is not function");
    return nullptr;
  }

  // Delete the previous reference if it exists
  if (logger_callback_ref != nullptr) {
    napi_delete_reference(env, logger_callback_ref);
  }

  napi_create_reference(env, args[0], 1, &logger_callback_ref);
  global_env = env;

  bool result_bool = set_logging_function([](const char *msg) {
    napi_value logger_callback;
    ASSERT_SILENT(napi_get_reference_value(global_env, logger_callback_ref, &logger_callback));

    napi_value string_arg;
    ASSERT_SILENT(napi_create_string_utf8(global_env, msg, NAPI_AUTO_LENGTH, &string_arg));

    napi_value global;
    ASSERT_SILENT(napi_get_global(global_env, &global));

    ASSERT_SILENT(napi_call_function(global_env, global, logger_callback, 1, &string_arg, nullptr));
  });

  ASSERT_STATUS(napi_get_boolean(env, result_bool, &result), "Cannot create bool result.")

  return result;
}


void CreateStringConstants(napi_env &env, napi_value &exports, const char *str) {
  napi_value type;
  ASSERT_SILENT(napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &type));
  ASSERT_SILENT(napi_set_named_property(env, exports, str, type));
}


// Initialize the addon
napi_value Init(napi_env env, napi_value exports) {

  napi_value GenerateSecretKeyFn;
  ASSERT_STATUS(napi_create_function(env, "generateSecretKey", NAPI_AUTO_LENGTH, GenerateSecretKey, nullptr,
                                     &GenerateSecretKeyFn), "Unable to wrap native function");

  napi_value GenerateSecretKeyBase64Fn;
  ASSERT_STATUS(
          napi_create_function(env, "generateSecretKeyBase64", NAPI_AUTO_LENGTH, GenerateSecretKeyBase64, nullptr,
                               &GenerateSecretKeyBase64Fn), "Unable to wrap native function");

  napi_value GetPublicKeyFromFn;
  ASSERT_STATUS(napi_create_function(env, "getPublicKeyFrom", NAPI_AUTO_LENGTH, GetPublicKeyFrom, nullptr,
                                     &GetPublicKeyFromFn), "Unable to wrap native function");

  napi_value CheckBase64EncodedX25519KeyFn;
  ASSERT_STATUS(napi_create_function(env, "checkBase64EncodedX25519Key", NAPI_AUTO_LENGTH, CheckBase64EncodedX25519Key,
                                     nullptr,
                                     &CheckBase64EncodedX25519KeyFn), "Unable to wrap native function");

  napi_value SetLoggingFunctionFn;
  ASSERT_STATUS(napi_create_function(env, "setLoggingFunction", NAPI_AUTO_LENGTH, SetLoggingFunction, nullptr,
                                     &SetLoggingFunctionFn), "Unable to wrap native function");

  napi_property_descriptor wireguard_tunnel_properties[] = {
          {"getPrivateKey", nullptr, WireguardTunnelGetPrivateKey, nullptr, nullptr, nullptr, napi_default, nullptr},
          {"getPublicKey",  nullptr, WireguardTunnelGetPublicKey,  nullptr, nullptr, nullptr, napi_default, nullptr},
          {"write",         nullptr, WireguardTunnelWrite,         nullptr, nullptr, nullptr, napi_default, nullptr},
          {"read",          nullptr, WireguardTunnelRead,          nullptr, nullptr, nullptr, napi_default, nullptr}
  };

  napi_value wireguard_tunnel_class;
  napi_define_class(env, "WireguardTunnel", NAPI_AUTO_LENGTH, WireguardTunnelConstructor, nullptr, 4,
                    wireguard_tunnel_properties,
                    &wireguard_tunnel_class);

  auto wg_ref_singleton= WireguardConstructorReference::GetInstance();

  wg_ref_singleton->SetReference(env, wireguard_tunnel_class);

  ASSERT_STATUS(napi_set_named_property(env, exports, "WireguardTunnel", wireguard_tunnel_class),
                "Cannot create Wireguard class");

  ASSERT_STATUS(napi_set_named_property(env, exports, "generateSecretKey", GenerateSecretKeyFn),
                "Failed to set exported generateSecretKey function");
  ASSERT_STATUS(napi_set_named_property(env, exports, "generateSecretKeyBase64", GenerateSecretKeyBase64Fn),
                "Failed to set exported generateSecretKeyBase64 function");
  ASSERT_STATUS(napi_set_named_property(env, exports, "getPublicKeyFrom", GetPublicKeyFromFn),
                "Failed to set exported generateSecretKeyBase64 function");
  ASSERT_STATUS(napi_set_named_property(env, exports, "checkBase64EncodedX25519Key", CheckBase64EncodedX25519KeyFn),
                "Failed to set exported generateSecretKeyBase64 function");
  ASSERT_STATUS(napi_set_named_property(env, exports, "setLoggingFunction", SetLoggingFunctionFn),
                "Failed to set exported generateSecretKeyBase64 function");

  CreateStringConstants(env, exports, "WIREGUARD_DONE");
  CreateStringConstants(env, exports, "WRITE_TO_NETWORK");
  CreateStringConstants(env, exports, "WIREGUARD_ERROR");
  CreateStringConstants(env, exports, "WRITE_TO_TUNNEL_IPV4");
  CreateStringConstants(env, exports, "WRITE_TO_TUNNEL_IPV6");

  return exports;
}

// Register the module
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)