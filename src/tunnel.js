const PLATFORMS = {
  ["darwin@arm64"]: '../build/mac_m/boringtunjs.node',
  ["darwin@intel"]: '../build/mac_intel/boringtunjs.node'
}

const pathToBindings = PLATFORMS[`${process.platform}@${process.arch}`]

if (!pathToBindings) {
  throw new Error(`Platform: ${process.platform} ${process.arch} not supported`)
}

const {
  generateSecretKeyBase64,
  generateSecretKey,
  getPublicKeyFrom,
  checkBase64EncodedX25519Key,
  setLoggingFunction,
  WireguardTunnel,
  WIREGUARD_DONE,
  WRITE_TO_NETWORK,
  WIREGUARD_ERROR,
  WRITE_TO_TUNNEL_IPV4,
  WRITE_TO_TUNNEL_IPV6,
} = require(pathToBindings)

/**
 * @typedef {Object} WireguardTunnel
 * @property {method} write
 */

/**
 * @param {string} privateKey
 * @returns {string}
 */
function getPublicKeyFromString(privateKey) {
  if (!checkBase64EncodedX25519Key(privateKey)) {
    throw new TypeError('Invalid input string key')
  }

  const privateKeyBuffer = Buffer.from(privateKey, 'base64')

  return getPublicKeyFromBuffer(privateKeyBuffer)
}

/**
 * @param {string} privateKeyBuffer
 * @returns {string}
 */
function getPublicKeyFromBuffer(privateKeyBuffer) {
  if (privateKeyBuffer.length !== 32) {
    throw new TypeError('Invalid buffer length')
  }

  const publicKeyBuffer = getPublicKeyFrom(privateKeyBuffer)

  return publicKeyBuffer.toString('base64')
}

/**
 * @returns {{privateKey: string, publicKey: string}}
 */
function generateKeyPair() {
  const privateBuffer = generateSecretKey()
  const publicBuffer = getPublicKeyFrom(privateBuffer)

  const privateKey = privateBuffer.toString('base64')
  const publicKey = publicBuffer.toString('base64')

  return {privateKey, publicKey}
}

/**
 * @returns {string}
 */
function generatePrivateKeyImpl() {
  return generateSecretKeyBase64()
}

/**
 * @param {string|buffer} privateKey
 * @throws
 */
function getPublicKeyFromImpl(privateKey) {
  if (typeof privateKey === 'string') {
    return getPublicKeyFromString(privateKey)
  }

  if (
    typeof privateKey === 'object' &&
    !!privateKey &&
    privateKey instanceof Buffer
  ) {
    return getPublicKeyFromBuffer(privateKey)
  }

  throw new TypeError('Invalid type of privateKey')
}

/**
 * @param {function} logger
 * @throws
 */
function setLoggingFunctionImpl(logger) {
  if (typeof logger !== 'function') {
    throw new TypeError('Invalid logger function')
  }

  setLoggingFunction(logger)
}

/**
 * @param {string} key
 * @return {boolean}
 */
function checkValidKey(key) {
  if (typeof key === 'string') {
    return checkBase64EncodedX25519Key(key)
  }

  if (typeof key === 'object' && !!key && key instanceof Buffer) {
    return checkBase64EncodedX25519Key(key.toString('base64'))
  }

  return false
}


module.exports = {
  generateKeyPair,
  generatePrivateKey: generatePrivateKeyImpl,
  getPublicKeyFrom: getPublicKeyFromImpl,
  setLoggingFunction: setLoggingFunctionImpl,
  checkValidKey,
  WireguardTunnel,
  WIREGUARD_DONE,
  WRITE_TO_NETWORK,
  WIREGUARD_ERROR,
  WRITE_TO_TUNNEL_IPV4,
  WRITE_TO_TUNNEL_IPV6,
}
