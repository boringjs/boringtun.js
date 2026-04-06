const {
  generateKeyPair,
  generatePrivateKey,
  getPublicKeyFrom,
  checkValidKey,
  WireguardTunnel,
} = require('./src/wireguard-tunnel.js')

const Wireguard = require('./src/wireguard.js')

const Logger = require('./src/utils/logger.js')

const Deque = require('./src/utils/deque.js')

module.exports = {
  generateKeyPair,
  generatePrivateKey,
  getPublicKeyFrom,
  checkValidKey,
  WireguardTunnel,
  Wireguard,
  Logger,
  Deque,
}
