#include "wireguard_global_wrapper.h"

napi_value GenerateSecretKey(napi_env env, napi_callback_info info) {
  struct x25519_key key = x25519_secret_key();
  napi_value result;
  void *bufferData;
  ASSERT_STATUS(napi_create_buffer_copy(env, sizeof(key.key), key.key, &bufferData, &result), "Buffer error");
  return result;
}

napi_value GenerateSecretKeyBase64(napi_env env, napi_callback_info info) {
  struct x25519_key key = x25519_secret_key();

  const char *key64 = x25519_key_to_base64(key);

  napi_value result;
//  ASSERT_STATUS(napi_create_string_utf8(env, key64, strlen(key64), &result), "Failed to create result string");
  TO_STRING(env, key64, strlen(key64), &result);

  x25519_key_to_str_free(key64);

  return result;
}

napi_value GetPublicKeyFrom(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_value result;
  x25519_key private_key;

  ASSERT_STATUS(napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), "Failed to parse arguments");

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Function expects one buffer argument.");
    return nullptr;
  }

  napi_valuetype val_type_key_private;
  ASSERT_STATUS(napi_typeof(env, args[0], &val_type_key_private), "Failing getting args type")

  bool private_key_is_buffer = false;
  ASSERT_STATUS(napi_is_buffer(env, args[0], &private_key_is_buffer), "Error checking is buffer");

  if (private_key_is_buffer) {
    size_t buffer_length;
    void *buffer_data;
    ASSERT_STATUS(napi_get_buffer_info(env, args[0], &buffer_data, &buffer_length),
                  "Cannot get buffer from private_key");

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

  TO_STRING(env, key64, strlen(key64), &result);

  x25519_key_to_str_free(key64);

  return result;
}

napi_value CheckBase64EncodedX25519Key(napi_env env, napi_callback_info info) {
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

  if (val_type_key != napi_string) {
    napi_throw_type_error(env, nullptr, "Input value is not string");
    return nullptr;
  }

  size_t str_length;
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[0], nullptr, 0, &str_length), "Cannot get string length")
  char *str = new char[str_length + 1];
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[0], str, str_length + 1, nullptr), "Cannot get string")

  bool result_raw = !!check_base64_encoded_x25519_key(str);

  delete[] str;
  ASSERT_STATUS(napi_get_boolean(env, result_raw, &result), "Cannot create bool result.")

  return result;
}
