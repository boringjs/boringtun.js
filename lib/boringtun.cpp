#define NAPI_VERSION 9

#include <node_api.h>
#include <iostream>

extern "C" {
#include "../boringtun/boringtun/src/wireguard_ffi.h"
}

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

napi_ref logger_callback_ref = nullptr;
napi_ref wireguard_constructor_ref = nullptr;
napi_env global_env = nullptr;

// Wrapper function for x25519_secret_key
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

class WireguardTunnel {
public:
  WireguardTunnel(
          std::string private_key,
          std::string public_key,
          std::string preshared_key,
          int32_t keep_alive,
          int32_t index)
          : private_key_(private_key),
            public_key_(public_key),
            preshared_key_(preshared_key),
            keep_alive_(keep_alive),
            index_(index),
            tunnel_(new_tunnel(
                    private_key_.c_str(),
                    public_key_.c_str(),
                    preshared_key_.size() > 0 ? preshared_key_.c_str() : nullptr,
                    keep_alive_,
                    index_)) {
  }

  wireguard_result Write(
          const uint8_t *src,
          uint32_t src_size,
          uint8_t *dst,
          uint32_t dst_size) {
    return wireguard_write(tunnel_, src, src_size, dst, dst_size);
  }

  wireguard_result Read(
          const uint8_t *src,
          uint32_t src_size,
          uint8_t *dst,
          uint32_t dst_size) {
    return wireguard_read(tunnel_, src, src_size, dst, dst_size);
  }

  wireguard_result Tick(
          uint8_t *dst,
          uint32_t dst_size) {
    return wireguard_tick(tunnel_, dst, dst_size);
  }

  wireguard_result ForceHandshake(
          uint8_t *dst,
          uint32_t dst_size) {
    return wireguard_force_handshake(tunnel_, dst, dst_size);
  }

  stats Stats() {
    return wireguard_stats(tunnel_);
  }

  const char *GetPrivateKey() {
    return private_key_.c_str();
  }

  const char *GetPublicKey() {
    return public_key_.c_str();
  }

  ~WireguardTunnel() {
    if (tunnel_ != nullptr) {
      tunnel_free(tunnel_);
    }
  }

  bool Valid() {
    return tunnel_ != nullptr;
  }

private:
  const std::string private_key_;
  const std::string public_key_;
  const std::string preshared_key_;
  int32_t keep_alive_;
  int32_t index_;
  wireguard_tunnel *tunnel_;
};

enum WG_OP_TYPE {
  READ = 1,
  WRITE = 2,
};

napi_value WireguardTunnelConstructor(napi_env env, napi_callback_info info) {
  napi_value js_this;
  size_t argc = 5;
  napi_value args[5];

  ASSERT_STATUS(napi_get_cb_info(env, info, &argc, args, &js_this, nullptr), "Cannot get args for constructor");

  if (argc != 5) {
    napi_throw_type_error(env, nullptr, "Function expects 5 arg");
    return nullptr;
  }

  // GET PRIVATE KEY
  napi_valuetype arg_type;
  ASSERT_STATUS(napi_typeof(env, args[0], &arg_type), "Failing getting args type")

  if (arg_type != napi_string) {
    napi_throw_type_error(env, nullptr, "Private key must be a string");
    return nullptr;
  }

  size_t private_key_length;
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[0], nullptr, 0, &private_key_length), "Cannot get string")
  char *private_key_ptr = new char[private_key_length + 1];
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[0], private_key_ptr, private_key_length + 1, nullptr),
                "Cannot get string")

  std::string private_key{private_key_ptr, private_key_length};

  delete[] private_key_ptr;

  bool is_valid_key = !!check_base64_encoded_x25519_key(private_key.c_str());


  if (!is_valid_key) {
    napi_throw_type_error(env, nullptr, "Invalid private key input");
    return nullptr;
  }

  // GET PUBLIC KEY
  ASSERT_STATUS(napi_typeof(env, args[1], &arg_type), "Failing getting args type")

  if (arg_type != napi_string) {
    napi_throw_type_error(env, nullptr, "Public key must be a string");
    return nullptr;
  }

  size_t public_key_length;
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[1], nullptr, 0, &public_key_length), "Cannot get string")
  char *public_key_ptr = new char[public_key_length + 1];
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[1], public_key_ptr, public_key_length + 1, nullptr),
                "Cannot get string")

  std::string public_key{public_key_ptr, public_key_length};

  delete[] public_key_ptr;

  is_valid_key = !!check_base64_encoded_x25519_key(public_key.c_str());

  if (!is_valid_key) {
    napi_throw_type_error(env, nullptr, "Invalid public key input");
    return nullptr;
  }


  // GET PRESHARED KEY
  ASSERT_STATUS(napi_typeof(env, args[2], &arg_type), "Failing getting args type")

  if (arg_type != napi_string) {
    napi_throw_type_error(env, nullptr, "Public key must be a string");
    return nullptr;
  }

  size_t preshared_key_length;
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[2], nullptr, 0, &preshared_key_length), "Cannot get string")
  char *preshared_key_ptr = new char[preshared_key_length + 1];
  ASSERT_STATUS(napi_get_value_string_utf8(env, args[2], preshared_key_ptr, preshared_key_length + 1, nullptr),
                "Cannot get string")

  std::string preshared_key{preshared_key_ptr, preshared_key_ptr};

  delete[] preshared_key_ptr;

  if (preshared_key_length > 0) {
    is_valid_key = !!check_base64_encoded_x25519_key(preshared_key.c_str());

    if (!is_valid_key) {
      napi_throw_type_error(env, nullptr, "Invalid public key input");
      return nullptr;
    }
  }

  // GET KEEP_ALIVE
  ASSERT_STATUS(napi_typeof(env, args[3], &arg_type), "Failing getting args type")

  if (arg_type != napi_number) {
    napi_throw_type_error(env, nullptr, "Public key must be a number");
    return nullptr;
  }

  int32_t keep_alive;
  ASSERT_STATUS(napi_get_value_int32(env, args[3], &keep_alive), "Cannot get int value")

  if (keep_alive < 1) {
    napi_throw_type_error(env, nullptr, "Invalid public key input");
    return nullptr;
  }

  // GET INDEX
  ASSERT_STATUS(napi_typeof(env, args[4], &arg_type), "Failing getting args type")

  if (arg_type != napi_number) {
    napi_throw_type_error(env, nullptr, "Index must be a number");
    return nullptr;
  }

  int32_t index;
  ASSERT_STATUS(napi_get_value_int32(env, args[4], &index), "Cannot get int value")

//  if (index < 1) {
//    napi_throw_type_error(env, nullptr, "Invalid index input");
//    return nullptr;
//  }

  auto *wg = new WireguardTunnel(
          private_key,
          public_key,
          preshared_key,
          keep_alive,
          index
  );

  if (!wg->Valid()) {
    delete wg;
    napi_throw_type_error(env, nullptr, "Cannot create tunnel");
    return nullptr;
  }

  napi_wrap(env, js_this, reinterpret_cast<void *>(wg), [](napi_env env, void *finalize_data, void *finalize_hint) {
    auto *wg = static_cast<WireguardTunnel *>(finalize_data);
    delete wg;
  }, nullptr, nullptr);

  return js_this;
}

napi_value WireguardTunnelGetPrivateKey(napi_env env, napi_callback_info info) {
  napi_value result;
  napi_value js_this;

  size_t argc = 0;
  napi_value args[0];
  ASSERT_STATUS(napi_get_cb_info(env, info, &argc, args, &js_this, nullptr), "Cannot get args from function");

  napi_value wireguard_constructor = NULL;
  ASSERT_STATUS(napi_get_reference_value(env, wireguard_constructor_ref, &wireguard_constructor),
                "Cannot get reference of constructor");

  bool is_instance = false;
  ASSERT_STATUS(napi_instanceof(env, js_this, wireguard_constructor, &is_instance), "Cannot check");

  if (!is_instance) {
    napi_throw_type_error(env, nullptr, "Invalid this");
    return nullptr;
  }

  WireguardTunnel *wg = nullptr;
  ASSERT_STATUS(napi_unwrap(env, js_this, reinterpret_cast<void **>(&wg)), "Cannot get instance of native wireguard");

  TO_STRING(env, wg->GetPrivateKey(), NAPI_AUTO_LENGTH, &result);
  return result;
}

napi_value WireguardTunnelReadWrite(napi_env env, napi_callback_info info, WG_OP_TYPE op_type) {
  napi_value result;
  napi_value js_this;

  size_t argc = 1;
  napi_value args[1];
  ASSERT_STATUS(napi_get_cb_info(env, info, &argc, args, &js_this, nullptr), "Cannot get args from function");

  napi_value wireguard_constructor = NULL;
  ASSERT_STATUS(napi_get_reference_value(env, wireguard_constructor_ref, &wireguard_constructor),
                "Cannot get reference of constructor");

  bool is_instance = false;
  ASSERT_STATUS(napi_instanceof(env, js_this, wireguard_constructor, &is_instance), "Cannot check");

  if (!is_instance) {
    napi_throw_type_error(env, nullptr, "Invalid this");
    return nullptr;
  }

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Function expects one buffer argument.");
    return nullptr;
  }

  napi_valuetype val_type;
  ASSERT_STATUS(napi_typeof(env, args[0], &val_type), "Failing getting args type")

  bool is_buffer = false;
  ASSERT_STATUS(napi_is_buffer(env, args[0], &is_buffer), "Error checking is buffer");

  if (!is_buffer) {
    napi_throw_type_error(env, nullptr, "Invalid type");
    return nullptr;
  }

  size_t buffer_length;
  void *buffer_data;
  ASSERT_STATUS(napi_get_buffer_info(env, args[0], &buffer_data, &buffer_length),
                "Cannot get buffer from private_key");

  WireguardTunnel *wg = nullptr;
  ASSERT_STATUS(napi_unwrap(env, js_this, reinterpret_cast<void **>(&wg)), "Cannot get instance of native wireguard");
  auto *src = static_cast<uint8_t *>(buffer_data);
  uint32_t src_size = buffer_length;
  uint32_t dst_size = 2000;
  auto *dst = new uint8_t[dst_size];
  memset(dst, 0, dst_size);

  auto read_result = op_type == WG_OP_TYPE::READ
                     ? wg->Read(src, src_size, dst, dst_size)
                     : wg->Write(src, src_size, dst, dst_size);

  napi_create_object(env, &result);

  std::string result_str;
  bool write_buffer;

  switch (read_result.op) {
    case result_type::WIREGUARD_DONE:
      result_str = "WIREGUARD_DONE";
      write_buffer = false;
      break;
    case result_type::WIREGUARD_ERROR:
      result_str = "WIREGUARD_ERROR";
      write_buffer = false;
      break;
    case result_type::WRITE_TO_NETWORK:
      result_str = "WRITE_TO_NETWORK";
      write_buffer = true;
      break;
    case result_type::WRITE_TO_TUNNEL_IPV4:
      result_str = "WRITE_TO_TUNNEL_IPV4";
      write_buffer = true;
      break;
    case result_type::WRITE_TO_TUNNEL_IPV6:
      result_str = "WRITE_TO_TUNNEL_IPV6";
      write_buffer = true;
      break;
  };

  napi_value type;
  ASSERT_STATUS(napi_create_string_utf8(env, result_str.c_str(), NAPI_AUTO_LENGTH, &type), "Cannot set value");
  ASSERT_STATUS(napi_set_named_property(env, result, "type", type), "Cannot set prop");

  if (write_buffer) {
    napi_value buffer;
    ASSERT_STATUS(napi_create_buffer_copy(env, read_result.size, reinterpret_cast<void ** >(dst), nullptr, &buffer),
                  "Cannot create buffer");
    napi_set_named_property(env, result, "data", buffer);
  }

  delete[] dst;

  return result;
}


napi_value WireguardTunnelRead(napi_env env, napi_callback_info info) {
  return WireguardTunnelReadWrite(env, info, WG_OP_TYPE::READ);
}

napi_value WireguardTunnelWrite(napi_env env, napi_callback_info info) {
  return WireguardTunnelReadWrite(env, info, WG_OP_TYPE::WRITE);

}

napi_value WireguardTunnelGetPublicKey(napi_env env, napi_callback_info info) {
  napi_value result;
  napi_value js_this;

  size_t argc = 0;
  napi_value args[0];
  ASSERT_STATUS(napi_get_cb_info(env, info, &argc, args, &js_this, nullptr), "Cannot get args from function");

  napi_value wireguard_constructor = NULL;
  ASSERT_STATUS(napi_get_reference_value(env, wireguard_constructor_ref, &wireguard_constructor),
                "Cannot get reference of constructor");

  bool is_instance = false;
  ASSERT_STATUS(napi_instanceof(env, js_this, wireguard_constructor, &is_instance), "Cannot check");

  if (!is_instance) {
    napi_throw_type_error(env, nullptr, "Invalid this");
    return nullptr;
  }

  WireguardTunnel *wg = nullptr;
  ASSERT_STATUS(napi_unwrap(env, js_this, reinterpret_cast<void **>(&wg)), "Cannot get instance of native wireguard");

  TO_STRING(env, wg->GetPublicKey(), NAPI_AUTO_LENGTH, &result);
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

  ASSERT_STATUS(napi_create_reference(env, wireguard_tunnel_class, 1, &wireguard_constructor_ref),
                "Cannot assert constructor to class");

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