const {
  generateKeyPair,
  generatePrivateKey,
  getPublicKeyFrom,
  setLoggingFunction,
  checkValidKey,
  WireguardTunnel,
  WireguardTunnelWrapper,
} = require('./src/tunnel.js')

const Wireguard = require('./src/wireguard.js')

const Logger = require('./src/utils/logger.js')

const Deque = require('./src/utils/deque.js')

module.exports = {
  generateKeyPair,
  generatePrivateKey,
  getPublicKeyFrom,
  setLoggingFunction,
  checkValidKey,
  WireguardTunnel,
  WireguardTunnelWrapper,
  Wireguard,
  Logger,
  Deque,
}
