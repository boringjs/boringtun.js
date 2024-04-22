#include "wireguard_global_wrapper.h"
#include "reference_singleton.h"

extern "C" {
#include "../boringtun/boringtun/src/wireguard_ffi.h"
}

static const std::string kLogFunctionName = "LogFunction";

napi_value GenerateSecretKey(napi_env env, napi_callback_info info) {
  struct x25519_key key = x25519_secret_key();
  napi_value result;
  napi_status status;
  void *bufferData;

  status = napi_create_buffer_copy(env, sizeof(key.key), key.key, &bufferData, &result);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Buffer error");
    return nullptr;
  }

  return result;
}

napi_value GenerateSecretKeyBase64(napi_env env, napi_callback_info info) {
  struct x25519_key key = x25519_secret_key();
  napi_status status;

  const char *key64 = x25519_key_to_base64(key);

  napi_value result;
  status = napi_create_string_utf8(env, key64, strlen(key64), &result);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to create result string");
    return nullptr;
  }

  x25519_key_to_str_free(key64);

  return result;
}

napi_value GetPublicKeyFrom(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_value result;
  x25519_key private_key;
  napi_status status;

  status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to parse arguments");
    return nullptr;
  }

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Function expects one buffer argument.");
    return nullptr;
  }

  napi_valuetype val_type_key_private;
  status = napi_typeof(env, args[0], &val_type_key_private);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }

  bool private_key_is_buffer = false;
  status = napi_is_buffer(env, args[0], &private_key_is_buffer);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Error checking is buffer");
    return nullptr;
  }

  if (private_key_is_buffer) {
    size_t buffer_length;
    void *buffer_data;
    status = napi_get_buffer_info(env, args[0], &buffer_data, &buffer_length);
    if (status != napi_ok) {
      napi_throw_error(env, nullptr, "Cannot get buffer from private_key");
      return nullptr;
    }

    if (buffer_length != 32) { // For example, checking for a specific length
      napi_throw_type_error(env, nullptr, "Buffer argument must have a length of 32.");
      return nullptr;
    }

    std::memcpy(private_key.key, buffer_data, sizeof(private_key.key));
  } else {
    napi_throw_type_error(env, nullptr, "Invalid type of first value");
    return nullptr;
  }

  auto public_key = x25519_public_key(private_key);

  const char *key64 = x25519_key_to_base64(public_key);

  status = napi_create_string_utf8(env, key64, strlen(key64), &result);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot convert to v8 string");
    return nullptr;
  }

  x25519_key_to_str_free(key64);

  return result;
}

napi_value CheckBase64EncodedX25519Key(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_value result;
  napi_status status;

  status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to parse arguments");
    return nullptr;
  }

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Function expects only one arg.");
    return nullptr;
  }

  napi_valuetype val_type_key;
  status = napi_typeof(env, args[0], &val_type_key);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }

  if (val_type_key != napi_string) {
    napi_throw_type_error(env, nullptr, "Input value is not string");
    return nullptr;
  }

  size_t str_length;
  status = napi_get_value_string_utf8(env, args[0], nullptr, 0, &str_length);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string length");
    return nullptr;
  }

  char *str = new char[str_length + 1];
  status = napi_get_value_string_utf8(env, args[0], str, str_length + 1, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string");
    return nullptr;
  }

  bool result_raw = !!check_base64_encoded_x25519_key(str);

  delete[] str;
  status = napi_get_boolean(env, result_raw, &result);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot create bool result.");
    return nullptr;
  }

  return result;
}

napi_status RegisterGlobalFunctions(napi_env env, napi_value exports) {
  napi_status status;
  napi_value SetLoggingFunctionFn;

  status = napi_create_function(env, "setLoggingFunction", NAPI_AUTO_LENGTH, SetLoggingFunction, nullptr,
                                &SetLoggingFunctionFn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Unable to wrap native function");
    return status;
  }

  status = napi_set_named_property(env, exports, "setLoggingFunction", SetLoggingFunctionFn);

  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to set exported generateSecretKeyBase64 function");
    return status;
  }

  napi_value GenerateSecretKeyFn;
  status = napi_create_function(env, "generateSecretKey", NAPI_AUTO_LENGTH, GenerateSecretKey, nullptr,
                                &GenerateSecretKeyFn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Unable to wrap native function");
    return status;
  }

  status = napi_set_named_property(env, exports, "generateSecretKey", GenerateSecretKeyFn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to set exported generateSecretKey function");
    return status;
  }

  napi_value GenerateSecretKeyBase64Fn;
  status = napi_create_function(env, "generateSecretKeyBase64", NAPI_AUTO_LENGTH, GenerateSecretKeyBase64, nullptr,
                                &GenerateSecretKeyBase64Fn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Unable to wrap native function");
    return status;
  }

  status = napi_set_named_property(env, exports, "generateSecretKeyBase64", GenerateSecretKeyBase64Fn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to set exported generateSecretKeyBase64 function");
    return status;
  }

  napi_value GetPublicKeyFromFn;
  status = napi_create_function(env, "getPublicKeyFrom", NAPI_AUTO_LENGTH, GetPublicKeyFrom, nullptr,
                                &GetPublicKeyFromFn); // , "");
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Unable to wrap native function");
    return status;
  }

  napi_value CheckBase64EncodedX25519KeyFn;
  status = napi_create_function(env, "checkBase64EncodedX25519Key", NAPI_AUTO_LENGTH, CheckBase64EncodedX25519Key,
                                nullptr,
                                &CheckBase64EncodedX25519KeyFn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Unable to wrap native function");
    return status;
  }

  status = napi_set_named_property(env, exports, "getPublicKeyFrom", GetPublicKeyFromFn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to set exported generateSecretKeyBase64 function");
    return status;
  }

  status = napi_set_named_property(env, exports, "checkBase64EncodedX25519Key", CheckBase64EncodedX25519KeyFn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to set exported generateSecretKeyBase64 function");
    return status;
  }

  return status; // todo return something
}

napi_value SetLoggingFunction(napi_env env, napi_callback_info info) {
  size_t argc;
  argc = 1;
  napi_value args[1];
  napi_value result;
  napi_status status;

  status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  if (status != napi_ok) {
    napi_throw_type_error(env, nullptr, "Failed to parse arguments");
    return nullptr;
  }

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Function expects only one arg.");
    return nullptr;
  }

  napi_valuetype val_type_key;
  status = napi_typeof(env, args[0], &val_type_key);
  if (status != napi_ok) {
    napi_throw_type_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }

  if (val_type_key != napi_function) {
    napi_throw_type_error(env, nullptr, "Input value is not function");
    return nullptr;
  }

  ReferenceSingleton::GetInstance()->SetReference(kLogFunctionName, env, args[0]);

  bool result_bool = set_logging_function([](const char *msg) {
    napi_status callback_status;

    if (!ReferenceSingleton::GetInstance()->IsRefExists(kLogFunctionName)) {
      return;
    }

    napi_value logger_callback;
    auto [logger_callback_ref, ref_env] = ReferenceSingleton::GetInstance()->GetRefEnv(kLogFunctionName);

    callback_status = napi_get_reference_value(ref_env, logger_callback_ref, &logger_callback);
    if (callback_status != napi_ok) {
      return;
    }

    napi_value string_arg;
    callback_status = napi_create_string_utf8(ref_env, msg, NAPI_AUTO_LENGTH, &string_arg);
    if (callback_status != napi_ok) {
      return;
    }

    napi_value global;
    callback_status = napi_get_global(ref_env, &global);
    if (callback_status != napi_ok) {
      return;
    }

    napi_call_function(ref_env, global, logger_callback, 1, &string_arg, nullptr);
  });

  status = napi_get_boolean(env, result_bool, &result);

  if (status != napi_ok) {
    napi_throw_type_error(env, nullptr, "Cannot create bool result.");
    return nullptr;
  }

  return result;
}

void CreateStringConstants(napi_env &env, napi_value &exports, const char *str) {
  napi_value type;
  napi_status status;
  status = napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &type);
  if (status != napi_ok) {
    napi_throw_type_error(env, nullptr, "Cannot create string");
    return;
  }

  status = napi_set_named_property(env, exports, str, type);
  if (status != napi_ok) {
    napi_throw_type_error(env, nullptr, "Cannot set property");
    return;
  }
}

napi_status RegisterGlobalConstants(napi_env env, napi_value exports) {
  napi_status status = napi_ok;

  CreateStringConstants(env, exports, "WIREGUARD_DONE");
  CreateStringConstants(env, exports, "WRITE_TO_NETWORK");
  CreateStringConstants(env, exports, "WIREGUARD_ERROR");
  CreateStringConstants(env, exports, "WRITE_TO_TUNNEL_IPV4");
  CreateStringConstants(env, exports, "WRITE_TO_TUNNEL_IPV6");

  return status;
}

