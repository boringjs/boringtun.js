const { EventEmitter } = require('events')
const IP4Address = require('./protocols/ip4-address.js')
const { WireguardTunnelWrapper } = require('./tunnel.js')

class Peer extends EventEmitter {
  #ip = new IP4Address(0)
  #tunnel = /** @type{WireguardTunnel | null} */ null
  #endpointAddress = new IP4Address(0)
  #endpointPort = 0

  constructor({ privateServerKey, publicKey, ip, keepAlive, index, endpointAddress, endpointPort }) {
    super()
    this.#ip = new IP4Address(ip)

    if (endpointAddress && endpointPort) {
      this.#endpointPort = endpointPort
      this.#endpointPort = endpointPort
    } else {
      this.#endpointPort = 0
      this.#endpointAddress = null
    }

    // todo create tick and test it
    // todo emit handshake

    this.#tunnel = new WireguardTunnelWrapper({
      privateKey: privateServerKey,
      publicKey,
      keepAlive,
      index,
    })
  }

  get ip() {
    return this.#ip
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

  routing({ data, type }) {
    if (type === WireguardTunnelWrapper.WIREGUARD_DONE) {
      console.log('Done')
      // do nothing
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_NETWORK) {
      const address = this.#endpointAddress.toString()
      const port = this.#endpointPort

      console.log(`write to tunnel ${data.length}`)
      this.emit('writeToTunnel', { address, port, data })
      return
    }

    if (type === WireguardTunnelWrapper.WIREGUARD_ERROR) {
      console.error('Error on wireguard')
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_TUNNEL_IPV4) {
      const peerIp = this.#ip
      this.emit('writeToIp4Layer', { peerIp, data })
      return
    }

    if (type === WireguardTunnelWrapper.WRITE_TO_TUNNEL_IPV6) {
      console.error('Do not support IPV6')
      return
    }

    throw new Error('Unknown operation')
  }

  read(msg) {
    this.routing(this.#tunnel.read(msg))
  }

  write(msg) {
    this.routing(this.#tunnel.write(msg))
  }

  forceHandshake() {
    // todo force handshake
  }
}

module.exports = Peer
