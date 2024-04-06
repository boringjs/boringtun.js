#pragma once

#include <iostream>

extern "C" {
#include "../boringtun/boringtun/src/wireguard_ffi.h"
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