#include "wireguard_tunnel_wrapper.h"

const std::string kWireguardConstructorName = "WireguardConstructor";

napi_value WireguardTunnelWrapperConstructor(napi_env env, napi_callback_info info) {
  napi_value js_this;
  size_t argc = 5;
  napi_value args[5];
  napi_status status;

  status = napi_get_cb_info(env, info, &argc, args, &js_this, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get args for constructor");
    return nullptr;
  }

  if (argc != 5) {
    napi_throw_type_error(env, nullptr, "Function expects 5 arg");
    return nullptr;
  }

  // GET PRIVATE KEY
  napi_valuetype arg_type;
  status = napi_typeof(env, args[0], &arg_type);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }


  if (arg_type != napi_string) {
    napi_throw_type_error(env, nullptr, "Private key must be a string");
    return nullptr;
  }

  size_t private_key_length;
  status = napi_get_value_string_utf8(env, args[0], nullptr, 0, &private_key_length);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string");
    return nullptr;
  }

  char *private_key_ptr = new char[private_key_length + 1];
  status = napi_get_value_string_utf8(env, args[0], private_key_ptr, private_key_length + 1, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string");
    return nullptr;
  }

  std::string private_key{private_key_ptr, private_key_length};

  delete[] private_key_ptr;

  bool is_valid_key = !!check_base64_encoded_x25519_key(private_key.c_str());


  if (!is_valid_key) {
    napi_throw_type_error(env, nullptr, "Invalid private key input");
    return nullptr;
  }

  // GET PUBLIC KEY
  status = napi_typeof(env, args[1], &arg_type);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }

  if (arg_type != napi_string) {
    napi_throw_type_error(env, nullptr, "Public key must be a string");
    return nullptr;
  }

  size_t public_key_length;
  status = napi_get_value_string_utf8(env, args[1], nullptr, 0, &public_key_length);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string");
    return nullptr;
  }

  char *public_key_ptr = new char[public_key_length + 1];
  status = napi_get_value_string_utf8(env, args[1], public_key_ptr, public_key_length + 1, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string");
    return nullptr;
  }

  std::string public_key{public_key_ptr, public_key_length};

  delete[] public_key_ptr;

  is_valid_key = !!check_base64_encoded_x25519_key(public_key.c_str());

  if (!is_valid_key) {
    napi_throw_type_error(env, nullptr, "Invalid public key input");
    return nullptr;
  }

  // GET PRESHARED KEY
  status = napi_typeof(env, args[2], &arg_type);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }

  if (arg_type != napi_string) {
    napi_throw_type_error(env, nullptr, "Public key must be a string");
    return nullptr;
  }

  size_t preshared_key_length;
  status = napi_get_value_string_utf8(env, args[2], nullptr, 0, &preshared_key_length);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string");
    return nullptr;
  }

  char *preshared_key_ptr = new char[preshared_key_length + 1];
  status = napi_get_value_string_utf8(env, args[2], preshared_key_ptr, preshared_key_length + 1, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get string");
    return nullptr;
  }

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
  status = napi_typeof(env, args[3], &arg_type);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }

  if (arg_type != napi_number) {
    napi_throw_type_error(env, nullptr, "Public key must be a number");
    return nullptr;
  }

  int32_t keep_alive;
  status = napi_get_value_int32(env, args[3], &keep_alive);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get int value");
    return nullptr;
  }

  if (keep_alive < 1) {
    napi_throw_type_error(env, nullptr, "Invalid public key input");
    return nullptr;
  }

  // GET INDEX
  status = napi_typeof(env, args[4], &arg_type);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failing getting args type");
    return nullptr;
  }

  if (arg_type != napi_number) {
    napi_throw_type_error(env, nullptr, "Index must be a number");
    return nullptr;
  }

  int32_t index;
  status = napi_get_value_int32(env, args[4], &index);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get int value");
    return nullptr;
  }

  if (index < 1) { // todo: check
    napi_throw_type_error(env, nullptr, "Invalid index input");
    return nullptr;
  }

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

napi_value WireguardTunnelWrapperGetPrivateKey(napi_env env, napi_callback_info info) {
  napi_value result;
  napi_value js_this;
  napi_status status;

  size_t argc = 0;
  status = napi_get_cb_info(env, info, &argc, nullptr, &js_this, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get args from function");
    return nullptr;
  }

  napi_value wireguard_constructor;
  auto ref = ReferenceSingleton::GetInstance()->GetRefEnv(kWireguardConstructorName).first;
  status = napi_get_reference_value(env, ref, &wireguard_constructor);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get reference of constructor");
    return nullptr;
  }

  bool is_instance = false;
  status = napi_instanceof(env, js_this, wireguard_constructor, &is_instance);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot check");
    return nullptr;
  }

  if (!is_instance) {
    napi_throw_type_error(env, nullptr, "Invalid this");
    return nullptr;
  }

  WireguardTunnel *wg = nullptr;
  status = napi_unwrap(env, js_this, reinterpret_cast<void **>(&wg));
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get instance of native wireguard");
    return nullptr;
  }

  status = napi_create_string_utf8(env, wg->GetPrivateKey(), NAPI_AUTO_LENGTH, &result);

  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Failed to convert to result string");
    return nullptr;
  }

  return result;
}

napi_value WireguardTunnelWrapperHandler(napi_env env, napi_callback_info info, WG_OP_TYPE op_type) {
  napi_value result;
  napi_value js_this;
  napi_status status;

  size_t argc_expect = ((op_type == WG_OP_TYPE::READ) || (op_type == WG_OP_TYPE::WRITE)) ? 1 : 0;
  size_t argc = argc_expect;
  napi_value args[argc];
  status = napi_get_cb_info(env, info, &argc, args, &js_this, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get args from function");
    return nullptr;
  }

  napi_value wireguard_constructor;
  auto ref = ReferenceSingleton::GetInstance()->GetRefEnv(kWireguardConstructorName).first;
  status = napi_get_reference_value(env, ref, &wireguard_constructor);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get reference of constructor");
    return nullptr;
  }

  bool is_instance = false;
  status = napi_instanceof(env, js_this, wireguard_constructor, &is_instance);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot check");
    return nullptr;
  }

  if (!is_instance) {
    napi_throw_type_error(env, nullptr, "Invalid this");
    return nullptr;
  }

  if (argc != argc_expect) {
    napi_throw_type_error(env, nullptr, "Invalid count of arguments");
    return nullptr;
  }

  WireguardTunnel *wg = nullptr;
  status = napi_unwrap(env, js_this, reinterpret_cast<void **>(&wg));
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get instance of native wireguard");
    return nullptr;
  }

  wireguard_result read_result = {result_type::WIREGUARD_ERROR, 0};

  uint32_t dst_size = 2000;
  auto *dst = new uint8_t[dst_size];
  memset(dst, 0, dst_size);

  if (op_type == WG_OP_TYPE::READ || op_type == WG_OP_TYPE::WRITE) {
    napi_valuetype val_type;
    status = napi_typeof(env, args[0], &val_type);
    if (status != napi_ok) {
      napi_throw_error(env, nullptr, "Failing getting args type");
      return nullptr;
    }

    bool is_buffer = false;
    status = napi_is_buffer(env, args[0], &is_buffer);
    if (status != napi_ok) {
      napi_throw_error(env, nullptr, "Error checking is buffer");
      return nullptr;
    }

    if (!is_buffer) {
      napi_throw_type_error(env, nullptr, "Invalid type");
      return nullptr;
    }

    size_t buffer_length;
    void *buffer_data;
    status = napi_get_buffer_info(env, args[0], &buffer_data, &buffer_length);
    if (status != napi_ok) {
      napi_throw_error(env, nullptr, "Cannot get buffer from private_key");
      return nullptr;
    }

    auto *src = static_cast<uint8_t *>(buffer_data);
    auto src_size = static_cast<uint32_t>(buffer_length);

    if (op_type == WG_OP_TYPE::READ) {
      read_result = wg->Read(src, src_size, dst, dst_size);
    } else { // if (op_type == WG_OP_TYPE::WRITE) {
      read_result = wg->Write(src, src_size, dst, dst_size);
    }
  } else if(op_type == WG_OP_TYPE::TICK || op_type == WG_OP_TYPE::FORCE_HANDSHAKE){
    if (op_type == WG_OP_TYPE::TICK) {
      read_result = wg->Tick(dst, dst_size);
    } else { // if (op_type == WG_OP_TYPE::FORCE_HANDSHAKE) {
      read_result = wg->ForceHandshake(dst, dst_size);
    }
  }


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
  status = napi_create_string_utf8(env, result_str.c_str(), NAPI_AUTO_LENGTH, &type);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot set value");
    return nullptr;
  }

  status = napi_set_named_property(env, result, "type", type);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot set prop");
    return nullptr;
  }

  if (write_buffer) {
    napi_value buffer;
    status = napi_create_buffer_copy(env, read_result.size, reinterpret_cast<void ** >(dst), nullptr, &buffer);
    if (status != napi_ok) {
      napi_throw_error(env, nullptr, "Cannot create buffer");
      return nullptr;
    }

    status = napi_set_named_property(env, result, "data", buffer);
    if (status != napi_ok) {
      napi_throw_error(env, nullptr, "Cannot set property");
      return nullptr;
    }
  }

  delete[] dst;

  return result;
}

napi_value WireguardTunnelWrapperRead(napi_env env, napi_callback_info info) {
  return WireguardTunnelWrapperHandler(env, info, WG_OP_TYPE::READ);
}

napi_value WireguardTunnelWrapperWrite(napi_env env, napi_callback_info info) {
  return WireguardTunnelWrapperHandler(env, info, WG_OP_TYPE::WRITE);
}

napi_value WireguardTunnelWrapperTick(napi_env env, napi_callback_info info) {
  return WireguardTunnelWrapperHandler(env, info, WG_OP_TYPE::TICK);
}

napi_value WireguardTunnelWrapperForceHandshake(napi_env env, napi_callback_info info) {
  return WireguardTunnelWrapperHandler(env, info, WG_OP_TYPE::FORCE_HANDSHAKE);
}

napi_value WireguardTunnelWrapperGetPublicKey(napi_env env, napi_callback_info info) {
  napi_value result;
  napi_value js_this;
  napi_status status;

  size_t argc = 0;
  status = napi_get_cb_info(env, info, &argc, nullptr, &js_this, nullptr);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get args from function");
    return nullptr;
  }

  napi_value wireguard_constructor;
  auto ref = ReferenceSingleton::GetInstance()->GetRefEnv(kWireguardConstructorName).first;
  status = napi_get_reference_value(env, ref, &wireguard_constructor);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get reference of constructor");
    return nullptr;
  }

  bool is_instance = false;
  status = napi_instanceof(env, js_this, wireguard_constructor, &is_instance);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot check");
    return nullptr;
  }

  if (!is_instance) {
    napi_throw_type_error(env, nullptr, "Invalid this");
    return nullptr;
  }

  WireguardTunnel *wg = nullptr;
  status = napi_unwrap(env, js_this, reinterpret_cast<void **>(&wg));
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot get instance of native wireguard");
    return nullptr;
  }

  status = napi_create_string_utf8(env, wg->GetPrivateKey(), NAPI_AUTO_LENGTH, &result);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot create v8 string");
    return nullptr;
  }

  return result;
}

napi_status RegisterWireguardTunnel(napi_env env, napi_value exports) {
  napi_status status;
  napi_property_descriptor wireguard_tunnel_properties[] = {
          {"getPrivateKey",  nullptr, WireguardTunnelWrapperGetPrivateKey,  nullptr, nullptr, nullptr, napi_default, nullptr},
          {"getPublicKey",   nullptr, WireguardTunnelWrapperGetPublicKey,   nullptr, nullptr, nullptr, napi_default, nullptr},
          {"write",          nullptr, WireguardTunnelWrapperWrite,          nullptr, nullptr, nullptr, napi_default, nullptr},
          {"read",           nullptr, WireguardTunnelWrapperRead,           nullptr, nullptr, nullptr, napi_default, nullptr},
          {"tick",           nullptr, WireguardTunnelWrapperTick,           nullptr, nullptr, nullptr, napi_default, nullptr},
          {"forceHandshake", nullptr, WireguardTunnelWrapperForceHandshake, nullptr, nullptr, nullptr, napi_default, nullptr}
  };

  napi_value wireguard_tunnel_class;
  status = napi_define_class(env, "WireguardTunnel", NAPI_AUTO_LENGTH, WireguardTunnelWrapperConstructor, nullptr, 6,
                             wireguard_tunnel_properties,
                             &wireguard_tunnel_class);
  if (status != napi_ok) {
    return status;
  }

  ReferenceSingleton::GetInstance()->SetReference(kWireguardConstructorName, env, wireguard_tunnel_class);

  status = napi_set_named_property(env, exports, "WireguardTunnel", wireguard_tunnel_class);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot create Wireguard class");
    return status;
  }

  return status;
}


