const {
  generateKeyPair,
  generatePrivateKey,
  getPublicKeyFrom,
  setLoggingFunction,
  checkValidKey,
  WireguardTunnel,
  WireguardTunnelWrapper
} = require('./src/tunnel.js')

const Wireguard = require('./src/wireguard.js')

module.exports = {
  generateKeyPair,
  generatePrivateKey,
  getPublicKeyFrom,
  setLoggingFunction,
  checkValidKey,
  WireguardTunnel,
  WireguardTunnelWrapper,
  Wireguard,
}
