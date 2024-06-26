const { EventEmitter } = require('events')
const IP4Address = require('./protocols/ip4-address.js')
const { WireguardTunnelWrapper } = require('./tunnel.js')
const Logger = require('./utils/logger.js')

const TICK_INTERVAL = 100
const FORCE_HADNSHAKE_DELTA = 1000

class Peer extends EventEmitter {
  #allowedIPs = /** @type{IP4Address[]}*/ []
  #tunnel = /** @type{WireguardTunnel|null} */ null
  #endpointAddress = null
  #endpointPort = 0
  #logger
  #tickIntervalId = null
  #publicKey = ''
  #lastForceHandshake = 0

  constructor({ logger, privateServerKey, publicKey, allowedIPs, keepAlive, index, endpointAddress, endpointPort }) {
    super()
    this.#allowedIPs = allowedIPs.split(',').map((ip) => new IP4Address(ip))
    this.#logger = logger || new Logger()
    this.#publicKey = publicKey

    this.#tunnel = new WireguardTunnelWrapper({
      privateKey: privateServerKey,
      publicKey,
      keepAlive,
      index,
    })

    this.#tickIntervalId = setInterval(this.#tick.bind(this), TICK_INTERVAL)

    if (endpointAddress && endpointPort) {
      this.#endpointPort = endpointPort
      this.#endpointAddress = endpointAddress
    }
    // todo create tick and test it
    // todo emit handshake
  }

  get endpointAddress() {
    return this.#endpointAddress
  }

  get endpointPort() {
    return this.#endpointPort
  }

  set endpointPort(v) {
    this.#endpointPort = v
  }

  /**
   * @param {number|string|Buffer|IP4Address} v
   */
  set endpointAddress(v) {
    this.#endpointAddress = new IP4Address(v)
  }

  get endpoint() {
    if (this.endpointAddress && this.endpointPort) {
      return `${this.endpointAddress}:${this.endpointPort}`
    }

    return ''
  }

  /**
   * @param {IP4Address} ip
   */
  match(ip) {
    return this.#allowedIPs.some((filterIP) => filterIP.match(ip))
  }

  #tick() {
    this.routing(this.#tunnel.tick())
  }

  routing({ data, type }) {
    if (type === WireguardTunnelWrapper.WIREGUARD_DONE) {
      // do nothing
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_NETWORK) {
      if (!this.endpoint) {
        return
      }
      const address = this.#endpointAddress.toString()
      const port = this.#endpointPort

      this.emit('writeToTunnel', { address, port, data })
      return
    }

    if (type === WireguardTunnelWrapper.WIREGUARD_ERROR) {
      this.#logger.error('Error on wireguard')
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_TUNNEL_IPV4) {
      this.emit('writeToIp4Layer', data)
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_TUNNEL_IPV6) {
      this.#logger.error('This implementation do not support IPV6')
      return
    }

    throw new Error('Unknown operation')
  }

  read(msg, address, port) {
    const result = this.#tunnel.read(msg)

    const isHandshake = msg.readUInt32LE(0) === 1 && msg.length > 90

    const isGood = result.type !== WireguardTunnelWrapper.WIREGUARD_ERROR

    if (address && port && isHandshake && isGood) {
      this.#logger.log(() => `for peer handshake: ${this.#publicKey}`)
      const oldEndpoint = this.endpoint

      this.endpointAddress = address
      this.endpointPort = port
      this.emit('updateEndpoint', oldEndpoint)
    }

    if (!isGood) {
      this.#logger.log(() => `force handshake for peer: ${this.#publicKey}`)
      this.forceHandshake()
    }

    this.routing(result)

    return isGood
  }

  write(msg) {
    this.routing(this.#tunnel.write(msg))
  }

  /**
   * @param {object} options
   * @param {Buffer} options.message
   * @param {string} options.address
   * @param {number} options.port
   * @return {boolean}
   */
  readHandshake({ message, address, port }) {
    const result = this.#tunnel.read(message)

    if (result.type === WireguardTunnelWrapper.WIREGUARD_ERROR) {
      return false
    }

    this.endpointAddress = address
    this.endpointPort = port

    setTimeout(this.routing.bind(this, result)) // for async
    return true
  }

  forceHandshake() {
    if (!this.endpoint) {
      this.#logger.debug(() => 'no endpoint for handshake')
      return
    }

    if (this.#lastForceHandshake + FORCE_HADNSHAKE_DELTA > Date.now()) {
      return
    }

    this.routing(this.#tunnel.forceHandshake())
  }

  getStat() {
    // todo native get stat
  }

  close() {
    this.#logger.debug(() => `close peer for ${this.#publicKey}`)
    clearInterval(this.#tickIntervalId)
  }
}

module.exports = Peer
