const { EventEmitter } = require('events')
const IP4Address = require('./protocols/ip4-address.js')
const { WireguardTunnel } = require('./wireguard-tunnel.js')
const Logger = require('./utils/logger.js')
const IPv4Packet = require('./protocols/ip4-packet')

const TICK_INTERVAL = 100
const FORCE_HANDSHAKE_DELTA = 1000
const PEER = '[PEER]'

/**
 * @typedef {Object} WriteToTunnelPayload
 * @property {string} address
 * @property {number} port
 * @property {(Buffer|string)} data
 */

/**
 * @event Peer#writeToTunnel
 * @type {function(WriteToTunnelPayload): void}
 */

/**
 * A peer that can send/receive data over a tunnel.
 *
 *
 * @extends EventEmitter
 * @fires Peer#writeToTunnel
 */
class Peer extends EventEmitter {
  #allowedIPs = /** @type{IP4Address[]}*/ []
  #tunnel = /** @type{WireguardTunnel|null} */ null
  #endpointAddress = null
  #endpointPort = 0
  #logger
  #tickIntervalId = null
  #publicKey = ''
  #lastForceHandshake = 0
  #name = ''

  constructor({
    logger,
    privateServerKey,
    publicKey,
    allowedIPs,
    keepAlive,
    index,
    endpointAddress,
    endpointPort,
    name,
  }) {
    super()
    this.#allowedIPs = allowedIPs.split(',').map((ip) => new IP4Address(ip))
    this.#logger = logger || new Logger()
    this.#publicKey = publicKey
    this.#name = name || this.#publicKey

    this.#tunnel = new WireguardTunnel({
      privateKey: privateServerKey,
      publicKey,
      keepAlive,
      index,
      logger: this.#logger,
    })

    if (endpointAddress && endpointPort) {
      this.#endpointPort = endpointPort
      this.#endpointAddress = endpointAddress
    }
  }

  get id() {
    return this.#publicKey
  }

  #startTick() {
    if (this.#tickIntervalId) {
      // this.#logger.debug(() => `Tick interval was set ${this.#publicKey}`)
      return
    }
    // this.#logger.debug(() => `Start tick interval ${this.#publicKey}`)
    this.#tickIntervalId = setInterval(this.#tick.bind(this), TICK_INTERVAL)
  }

  #stopTick() {
    this.#logger.debug(() => `Stop tick interval for ${this.#publicKey}`)
    clearInterval(this.#tickIntervalId)
    this.#tickIntervalId = null
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

  get name() {
    return this.#name
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

  /*
   * @param {WriteToTunnelPayload} payload
   */
  #emitWriteToTunnel({ address, port, data }) {
    this.emit('writeToTunnel', { address, port, data })
  }

  /**
   * @param {Buffer} data
   */
  #emitWriteToIPv4Layer(data) {
    const ip4Packet = new IPv4Packet(data)
    ip4Packet.peerId = this.id
    this.emit('writeToIp4Layer', ip4Packet)
  }

  /**
   * @param {IP4Address} ip
   */
  match(ip) {
    return this.#allowedIPs.some((filterIP) => filterIP.match(ip))
  }

  #tick() {
    this.routing({ src: 'tick', ...this.#tunnel.tick() })
  }

  routing({ data, type, src }) {
    if (type === WireguardTunnel.WIREGUARD_DONE) {
      // do nothing
      return
    }

    if (type === WireguardTunnel.WRITE_TO_NETWORK) {
      if (!this.endpoint) {
        return
      }
      const address = this.#endpointAddress.toString()
      const port = this.#endpointPort

      this.#emitWriteToTunnel({ address, port, data })
      return
    }

    if (type === WireguardTunnel.WIREGUARD_ERROR) {
      this.#logger.error(() => {
        const f = `${PEER}[${this.name || this.#publicKey}][${src}]`
        const msg = `Error on wireguard.`

        return { f, msg }
      })

      if (src === 'tick') {
        this.#stopTick()
      }
      return
    }

    if (type === WireguardTunnel.WRITE_TO_TUNNEL_IPV4) {
      this.#emitWriteToIPv4Layer(data)
      return
    }

    if (type === WireguardTunnel.WRITE_TO_TUNNEL_IPV6) {
      this.#logger.error('This implementation do not support IPV6')
      return
    }

    throw new Error('Unknown operation')
  }

  #emitUpdateEndpoint({ peer = this, oldEndpoint, newEndpoint = this.endpoint }) {
    this.emit('updateEndpoint', { peer, oldEndpoint, newEndpoint })
  }

  read(msg, address, port) {
    const result = { ...this.#tunnel.read(msg), src: 'read' }

    const isHandshake = msg.length > 90 && msg.readUInt32LE(0) === 1

    const isGood = result.type !== WireguardTunnel.WIREGUARD_ERROR

    if (address && port && isHandshake && isGood) {
      this.#logger.log(() => `for peer handshake: ${this.#publicKey}`)
      const oldEndpoint = this.endpoint

      this.endpointAddress = address
      this.endpointPort = port
      this.#emitUpdateEndpoint({ oldEndpoint })
      this.#startTick()
    }

    if (!isGood) {
      this.#logger.log(() => {
        const f = `${PEER}[${this.#name || this.#publicKey}]`
        const msg = `force handshake for peer`

        return { f, msg }
      })
      this.forceHandshake()
    }

    this.routing(result)

    return isGood
  }

  write(msg) {
    this.routing({ ...this.#tunnel.write(msg), src: 'write' })
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

    if (result.type === WireguardTunnel.WIREGUARD_ERROR) {
      return false
    }

    this.endpointAddress = address
    this.endpointPort = port

    setTimeout(this.routing.bind(this, result)) // for async
    return true
  }

  forceHandshake() {
    if (!this.endpoint) {
      this.#logger.debug(() => {
        const f = `${PEER}[${this.#name || this.#publicKey}]`
        const msg = 'no endpoint for handshake'
        return { f, msg }
      })
      return
    }

    if (this.#lastForceHandshake + FORCE_HANDSHAKE_DELTA > Date.now()) {
      return
    }

    this.#startTick()

    this.routing({ ...this.#tunnel.forceHandshake(), src: 'forceHandshake' })
  }

  getStat() {
    const tunnel = this.#tunnel
      ? this.#tunnel.getStats()
      : { txBytes: 0, rxBytes: 0, lastHandshakeRtt: null, lastHandshake: 0 }
    return {
      publicKey: this.#publicKey,
      name: this.#name,
      endpoint: this.endpoint,
      ...tunnel,
    }
  }

  close() {
    this.#logger.debug(() => `close peer for ${this.#publicKey}`)
    clearInterval(this.#tickIntervalId)
    this.#tickIntervalId = null
    this.removeAllListeners()
    this.#tunnel = null
  }
}

module.exports = Peer
