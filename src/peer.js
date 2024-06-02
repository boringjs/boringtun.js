const { EventEmitter } = require('events')
const IP4Address = require('./protocols/ip4-address.js')
const { WireguardTunnelWrapper } = require('./tunnel.js')

class Peer extends EventEmitter {
  #allowedIPs = new IP4Address(0)
  #tunnel = /** @type{WireguardTunnel | null} */ null
  #endpointAddress = null
  #endpointPort = 0

  constructor({ privateServerKey, publicKey, allowedIPs, keepAlive, index, endpointAddress, endpointPort }) {
    super()
    this.#allowedIPs = new IP4Address(allowedIPs)

    this.#tunnel = new WireguardTunnelWrapper({
      privateKey: privateServerKey,
      publicKey,
      keepAlive,
      index,
    })

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
    return this.#allowedIPs.match(ip)
  }

  routing({ data, type }) {
    if (type === WireguardTunnelWrapper.WIREGUARD_DONE) {
      // do nothing
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_NETWORK) {
      const address = this.#endpointAddress.toString()
      const port = this.#endpointPort

      this.emit('writeToTunnel', { address, port, data })
      return
    }

    if (type === WireguardTunnelWrapper.WIREGUARD_ERROR) {
      console.error('Error on wireguard')
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_TUNNEL_IPV4) {
      this.emit('writeToIp4Layer', data)
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_TUNNEL_IPV6) {
      console.error('This implementation do not support IPV6')
      return
    }

    throw new Error('Unknown operation')
  }

  read(msg) {
    return this.routing(this.#tunnel.read(msg))
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
    // todo force handshake
  }
}

module.exports = Peer
