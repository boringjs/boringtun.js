const dgram = require('dgram')
const { EventEmitter } = require('events')
const IPLayer = require('./protocols/ip-layer.js')
const { checkValidKey, getPublicKeyFrom } = require('./wireguard-tunnel.js')
const Peer = require('./peer.js')
const IP4Address = require('./protocols/ip4-address.js')
const Logger = require('./utils/logger.js')

const WG = '[WG]'

class Wireguard extends EventEmitter {
  #ipLayer = /** @type{IPLayer} */ null
  #privateKey = ''
  #publicKey = ''
  #listenPort = 0
  #server /** @type {Socket}*/ = dgram.createSocket('udp4')
  #address = new IP4Address(0)
  #peers = /** @type{Peer[]}*/ []
  #peersMap = /** @type{Map<string, Peer>}*/ new Map()
  #mapEndpointIpToPeer = /** @type{Map<string,Peer>} */ new Map()
  #index = 1
  #logLevel = 0
  #logger /** @type {Logger} */ = null
  #TCPSocketFactory
  #UDPSocketFactory

  constructor({ privateKey, listenPort, address, logLevel = 0, logger = new Logger({ logLevel }) }) {
    if (typeof privateKey !== 'string' || !checkValidKey(privateKey)) {
      throw new Error('Invalid privateKey')
    }

    if (typeof listenPort !== 'number' && listenPort > 0 && listenPort << 15) {
      throw new Error('Invalid listenPort')
    }

    if (
      typeof logger.info !== 'function' ||
      typeof logger.log !== 'function' ||
      typeof logger.error !== 'function' ||
      typeof logger.debug !== 'function'
    ) {
      throw new Error('Invalid logger')
    }

    super()

    this.#privateKey = privateKey
    this.#publicKey = getPublicKeyFrom(privateKey)
    this.#listenPort = listenPort
    this.#address = new IP4Address(address)
    this.#logLevel = logLevel
    this.#logger = logger
  }

  getPeers() {
    return this.#peers.map((peer) => peer.endpoint)
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

  get address() {
    return this.#address
  }

  getPeerByKey(key) {
    return this.#peersMap.get(key)
  }

  addTCPSocketFactory(tcpSocketFactory) {
    if (typeof tcpSocketFactory !== 'function') {
      throw new Error('Invalid tcpSocketFactory')
    }
    if (this.#TCPSocketFactory) {
      throw new Error('TCPSocketFactory already set')
    }

    // this.#logger.debug(() => `Add TCPSocketFactory`)
    this.#TCPSocketFactory = tcpSocketFactory

    return this
  }

  addUDPSocketFactory(udpSocketFactory) {
    if (typeof udpSocketFactory !== 'function') {
      throw new Error('Invalid udpSocketFactory')
    }
    if (this.#UDPSocketFactory) {
      throw new Error('UDPSocketFactory already set')
    }

    // this.#logger.debug(() => `Add UDPSocketFactory`)
    this.#UDPSocketFactory = udpSocketFactory

    return this
  }

  #updatePeerEndpoint({ peer, oldEndpoint, newEndpoint }) {
    if (oldEndpoint) {
      this.#mapEndpointIpToPeer.delete(oldEndpoint)
    }

    this.#mapEndpointIpToPeer.set(newEndpoint, peer)
  }

  addPeer({ publicKey, allowedIPs, keepAlive = 25, endpoint, name }) {
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
      name,
    })

    this.#peersMap.set(publicKey, peer)
    this.#peers.push(peer)

    if (peer.endpoint) {
      this.#mapEndpointIpToPeer.set(endpoint, peer)
    }

    peer.on('writeToTunnel', this.#onWriteToTunnel.bind(this))
    peer.on('writeToIp4Layer', this.#onWriteToIPv4.bind(this))
    peer.on('updateEndpoint', this.#updatePeerEndpoint.bind(this))

    return this
  }

  removePeer(publicKey) {
    const peer = this.#peersMap.get(publicKey)
    if (!peer) return false

    peer.close()
    this.#peersMap.delete(publicKey)
    this.#peers = this.#peers.filter((p) => p.id !== publicKey)
    if (peer.endpoint) {
      this.#mapEndpointIpToPeer.delete(peer.endpoint)
    }
    return true
  }

  listen() {
    this.#createServerListeners()
    this.#ipLayer = new IPLayer({
      logger: this.#logger,
      tcpSocketFactory: this.#TCPSocketFactory,
      udpSocketFactory: this.#UDPSocketFactory,
    })
    this.#ipLayer.on('ipv4ToTunnel', this.#onMessageFromIPLayer.bind(this))
    this.#server.bind(this.#listenPort, this.#onListening.bind(this))
    this.#logger.info(() => {
      const f = `[WG]`
      const msg = `Start listen on port ${this.#listenPort}`
      return { f, msg }
    })
  }

  #route(ip) {
    return this.#peers.find((peer) => peer.match(ip))
  }

  close() {
    for (const peer of this.#peers) {
      peer.close()
    }
    this.#peers = []
    this.#peersMap.clear()
    this.#mapEndpointIpToPeer.clear()

    if (this.#ipLayer) {
      this.#ipLayer.removeAllListeners()
      this.#ipLayer.close()
      this.#ipLayer = null
    }

    if (this.#server) {
      this.#server.removeAllListeners()
      this.#server.close()
      this.#server = null
    }

    this.removeAllListeners()
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
   * @param {IPv4Packet} ip4Packet
   */
  #onWriteToIPv4(ip4Packet) {
    const peer = this.#route(ip4Packet.destinationIP)
    if (peer) {
      return peer.write(ip4Packet.toBuffer())
    }

    // this.#logger.debug(() => {
    //   const tcpMsg = ip4Packet.protocol === TCP ? JSON.stringify(ip4Packet.getTCPMessage().debugView(), null, 2) : ''

    // return `to ip layer (${ip4Packet.protocol}): ${ip4Packet.sourceIP} -> ${ip4Packet.destinationIP} (${tcpMsg})`
    // })

    this.#ipLayer.send(ip4Packet)
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
      this.#logger.info(() => {
        const f = WG
        const msg = 'Start working'
        return { f, msg }
      })
    }

    this.#peers.forEach((peer) => peer.forceHandshake())
  }

  getStat() {
    return {
      publicKey: this.#publicKey,
      listenPort: this.#listenPort,
      address: this.#address.toString(),
      peers: this.#peers.map((peer) => peer.getStat()),
      connections: this.#ipLayer ? this.#ipLayer.getStats() : null,
    }
  }
}

module.exports = Wireguard
