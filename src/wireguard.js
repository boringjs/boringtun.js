const dgram = require('dgram')
const { EventEmitter } = require('events')
const IPLayer = require('./protocols/ip-layer.js')
const { checkValidKey, getPublicKeyFrom } = require('./tunnel.js')
const Peer = require('./peer.js')
const IP4Address = require('./protocols/ip4-address.js')
const IPv4Packet = require('./protocols/ip4-packet.js')
const Logger = require('./utils/logger.js')

class Wireguard extends EventEmitter {
  #ipLayer = /** @type{IPLayer} */ null
  #privateKey = ''
  #publicKey = ''
  #listenPort = 0
  #server /** @type {Socket}*/ = dgram.createSocket('udp4')
  #address = new IP4Address(0)
  #peers = /** @type{Peer[]}*/ []
  #mapEndpointIpToPeer = /** @type{Map<string,Peer>} */ new Map()
  #index = 1
  #logLevel = 0
  #logger

  constructor({ privateKey, listenPort, address, logLevel = 0, logger, getTCPSocket }) {
    if (typeof privateKey !== 'string' || !checkValidKey(privateKey)) {
      throw new Error('Invalid privateKey')
    }

    if (typeof listenPort !== 'number' && listenPort > 0 && listenPort << 15) {
      throw new Error('Invalid listenPort')
    }
    super()

    this.#privateKey = privateKey
    this.#publicKey = getPublicKeyFrom(privateKey)
    this.#listenPort = listenPort
    this.#address = new IP4Address(address)
    this.#createServerListeners()
    this.#logLevel = logLevel
    this.#logger = logger || new Logger({ logLevel })
    this.#ipLayer = new IPLayer({ logger: this.#logger, getTCPSocket })
    this.#ipLayer.on('ipv4ToTunnel', this.#onMessageFromIPLayer.bind(this))
  }

  /**
   * @return {string}
   */
  get publicKey() {
    return this.#publicKey
  }

  /**
   * @return {string}
   */
  get privateKey() {
    return this.#privateKey
  }

  /**
   * @return {number}
   */
  get listenPort() {
    return this.#listenPort
  }

  #updatePeerEndpoint({ peer, oldEndpoint, newEndpoint }) {
    if (oldEndpoint) {
      this.#mapEndpointIpToPeer.delete(oldEndpoint)
    }

    this.#mapEndpointIpToPeer.set(newEndpoint, peer)
  }

  addPeer({ publicKey, allowedIPs, keepAlive = 25, endpoint }) {
    const [endpointAddress, endpointPort] = (endpoint || '').split(':')

    const peer = new Peer({
      privateServerKey: this.privateKey,
      publicKey,
      allowedIPs,
      keepAlive,
      index: this.#index++,
      endpointPort,
      endpointAddress,
      logger: this.#logger,
    })

    this.#peers.push(peer)

    if (peer.endpoint) {
      this.#mapEndpointIpToPeer.set(endpoint, peer)
    }

    peer.on('writeToTunnel', this.#onWriteToTunnel.bind(this))
    peer.on('writeToIp4Layer', this.#onWriteToIPv4.bind(this))
    peer.on('updateEndpoint', this.#updatePeerEndpoint.bind(this))

    return this
  }

  listen() {
    this.#server.bind(this.#listenPort, this.#onListening.bind(this))
  }

  #route(ip) {
    return this.#peers.find((peer) => peer.match(ip))
  }

  close() {
    // todo: close tcp layer
    // todo: stop server
    // todo: stop peers
  }

  /**
   * @param {IPv4Packet} ipv4Packet
   */
  #onMessageFromIPLayer(ipv4Packet) {
    const peer = this.#route(ipv4Packet.destinationIP)
    if (!peer) {
      return
    }

    peer.write(ipv4Packet.toBuffer())
  }

  /**
   * @param {WriteToTunnelPayload} payload
   */
  #onWriteToTunnel({ address, port, data }) {
    this.#server.send(data, port, address, this.#onWriteToTunnelError.bind(this))
  }

  #onWriteToTunnelError(error) {
    if (error) {
      this.#logger.error(() => error)
    }
  }

  /**
   * @param {Buffer} data
   */
  #onWriteToIPv4(data) {
    const ipv4Packet = new IPv4Packet(data)
    const peer = this.#route(ipv4Packet.destinationIP)
    if (peer) {
      return peer.write(ipv4Packet.toBuffer())
    }

    this.#logger.debug(
      () =>
        `ip layer (${ipv4Packet.protocol}): ${ipv4Packet.sourceIP} -> ${ipv4Packet.destinationIP} (${data.length} bytes): ${data.toString('hex')}`,
    )

    this.#ipLayer.send(ipv4Packet)
  }

  /**
   * @param {Buffer} message
   * @param {{address: string, port: number}}
   */
  #onMessage(message, { address, port }) {
    const endpoint = `${address}:${port}`

    if (this.#mapEndpointIpToPeer.has(endpoint)) {
      this.#mapEndpointIpToPeer.get(endpoint).read(message)
      return
    }

    this.#peers.some((peer) => peer.read(message, address, port))
  }

  #onError(error) {
    this.#logger.error(error) // todo
  }

  #createServerListeners() {
    this.#server.on('error', this.#onError.bind(this))
    this.#server.on('message', this.#onMessage.bind(this))
  }

  #onListening() {
    if (this.#logLevel) {
      this.#logger.log('Start working')
    }

    this.#peers.forEach((peer) => peer.forceHandshake())
  }

  getStat() {
    // todo get stat
  }
}

module.exports = Wireguard
