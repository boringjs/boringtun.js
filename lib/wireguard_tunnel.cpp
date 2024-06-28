#include "./wireguard_tunnel.h"

int WireguardTunnel::id_counter_ = 1;

WireguardTunnel::WireguardTunnel(std::string private_key, std::string public_key, std::string pre_shared_key,
                                 int32_t keep_alive, int32_t index)
        : private_key_(private_key),
          peer_public_key_(public_key),
          pre_shared_key_(pre_shared_key),
          keep_alive_(keep_alive),
          index_(index),
          tunnel_(new_tunnel(
                  private_key.c_str(),
                  public_key.c_str(),
                  pre_shared_key.empty() ? nullptr : pre_shared_key_.c_str(),
                  keep_alive_,
                  index_)) {
  id_ = id_counter_++;
}

wireguard_result WireguardTunnel::Write(const uint8_t *src, uint32_t src_size, uint8_t *dst, uint32_t dst_size) {
  return wireguard_write(tunnel_, src, src_size, dst, dst_size);
}

wireguard_result WireguardTunnel::Read(const uint8_t *src, uint32_t src_size, uint8_t *dst, uint32_t dst_size) {
  return wireguard_read(tunnel_, src, src_size, dst, dst_size);
}

wireguard_result WireguardTunnel::Tick(uint8_t *dst, uint32_t dst_size) {
  return wireguard_tick(tunnel_, dst, dst_size);
}

wireguard_result WireguardTunnel::ForceHandshake(uint8_t *dst, uint32_t dst_size) {
  return wireguard_force_handshake(tunnel_, dst, dst_size);
}

stats WireguardTunnel::Stats() {
  return wireguard_stats(tunnel_);
}

const char *WireguardTunnel::GetPrivateKey() {
  return private_key_.c_str();
}

const char *WireguardTunnel::GetPeerPublicKey() {
  return peer_public_key_.c_str();
}

WireguardTunnel::~WireguardTunnel() {
  if (tunnel_ != nullptr) {
    tunnel_free(tunnel_);
  }
}

bool WireguardTunnel::Valid() {
  return tunnel_ != nullptr;
}

WireguardTunnel::WireguardTunnel(WireguardTunnel &&other) noexcept
        : private_key_(std::move(other.private_key_)),
          peer_public_key_(std::move(other.peer_public_key_)),
          pre_shared_key_(std::move(other.pre_shared_key_)),
          keep_alive_(other.keep_alive_),
          index_(other.index_),
          tunnel_(other.tunnel_),
          id_(other.id_) {
  other.tunnel_ = nullptr;
}

WireguardTunnel &WireguardTunnel::operator=(WireguardTunnel &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  private_key_ = std::move(other.private_key_);
  peer_public_key_ = std::move(other.peer_public_key_);
  pre_shared_key_ = std::move(other.pre_shared_key_);
  keep_alive_ = other.keep_alive_;
  index_ = other.index_;
  tunnel_ = other.tunnel_;
  id_ = other.id_;
  other.tunnel_ = nullptr;
  return *this;
}
