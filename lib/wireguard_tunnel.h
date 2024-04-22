#pragma once

#include <string>

extern "C" {
#include "../boringtun/boringtun/src/wireguard_ffi.h"
}

class WireguardTunnel {
public:
  static int id_counter_;

  WireguardTunnel(
          std::string private_key,
          std::string public_key,
          std::string preshared_key,
          int32_t keep_alive,
          int32_t index);

  wireguard_result Write(
          const uint8_t *src,
          uint32_t src_size,
          uint8_t *dst,
          uint32_t dst_size);

  wireguard_result Read(
          const uint8_t *src,
          uint32_t src_size,
          uint8_t *dst,
          uint32_t dst_size);

  wireguard_result Tick(
          uint8_t *dst,
          uint32_t dst_size);

  wireguard_result ForceHandshake(
          uint8_t *dst,
          uint32_t dst_size);

  stats Stats();

  const char *GetPrivateKey();

  const char *GetPublicKey();

  ~WireguardTunnel();

  bool Valid();

private:
  const std::string private_key_;
  const std::string public_key_;
  const std::string preshared_key_;
  int32_t keep_alive_;
  int32_t index_;
  wireguard_tunnel *tunnel_;
  int id_;
};