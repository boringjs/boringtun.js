const dgram = require('dgram')
const { EventEmitter } = require('events')
const IPLayer = require('./protocols/ip-layer.js')
const { checkValidKey, getPublicKeyFrom } = require('./tunnel.js')
const Peer = require('./peer.js')
const IP4Address = require('./protocols/ip4-address.js')
const IPv4Packet = require('./protocols/ip4-packet.js')

class Wireguard extends EventEmitter {
  #ipLayer = new IPLayer()
  #privateKey = ''
  #publicKey = ''
  #listenPort = 0
  #server /** @type {Socket}*/ = dgram.createSocket('udp4')
  #address = new IP4Address(0)
  #peers = /** @type{Set<Peer>}*/ new Set()
  #mapEndpointIpToPeer = /** @type{Map<string,Peer>} */ new Map()
  #index = 1
  #logLevel = 0
  #log = () => {}

  constructor({ privateKey, listenPort, address, logLevel = 0, log = console.log }) {
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
    this.#log = log
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
    })

    this.#peers.add(publicKey, peer)

    if (peer.endpoint) {
      this.#mapEndpointIpToPeer.set(endpoint, peer)
    }

    peer.on('writeToTunnel', ({ address, port, data }) => {
      // console.log(`tunnel ${data.length} -> ${address}:${port}`)
      this.#onWriteToTunnel({ address, port, data })
    })

    peer.on('writeToIp4Layer', (data) => {
      this.#onWriteToIPv4(data)
    })

    return this
  }

  listen() {
    this.#server.bind(this.#listenPort, this.#onListening.bind(this))
  }

  #route(ip) {
    for (const peer of this.#peers) {
      if (peer.match(ip)) {
        return peer
      }
    }

    return null
  }

  #onMessageFromIPLayer(ipv4Packet) {
    const peer = this.#route(ipv4Packet.destinationIP)
    if (!peer) {
      return
    }

    peer.write(ipv4Packet.toBuffer())
  }

  #onWriteToTunnel({ address, port, data }) {
    this.#server.send(data, port, address, (error) => (error ? console.error(`Error onsend to client${error}`) : null))
  }

  #onWriteToIPv4(data) {
    const ipv4Packet = new IPv4Packet(data)
    const peer = this.#route(ipv4Packet.destinationIP)
    if (peer) {
      if (this.#logLevel > 1) {
        console.log(`back to peer ${peer.allowedIPs} ${ipv4Packet.destinationIP}`)
      }
      return peer.write(ipv4Packet.toBuffer())
    }
    if (this.#logLevel > 1) {
      console.log(`goto tcp layer -> ${ipv4Packet.destinationIP}`)
    }
    this.#ipLayer.receivePacket(ipv4Packet)
  }

  /**
   * @param {Buffer} message
   * @param {{address: string, port: number}}
   */
  #onMessage(message, { address, port }) {
    if (this.#logLevel > 2) {
      // console.log(`message from ${address}`)
    }

    const endpoint = `${address}:${port}`

    if (this.#mapEndpointIpToPeer.has(endpoint)) {
      return this.#mapEndpointIpToPeer.get(endpoint).read(message)
    }

    if (message.readUInt32LE(0) !== 1 || message.length < 32) {
      // not handshake
      return
    }

    for (const peer of this.#peers) {
      const oldEndpoint = peer.endpoint
      if (!peer.readHandshake({ message, address, port })) {
        console.log('error with handshake')
        continue
      }

      if (oldEndpoint) {
        this.#mapEndpointIpToPeer.delete(oldEndpoint)
      }

      this.#mapEndpointIpToPeer.set(peer.endpoint, peer)
      return
    }
  }

  /**
   * @param {Buffer} data
   */
  #onError(data) {
    console.error(data) // todo
  }

  #createServerListeners() {
    this.#server.on('error', this.#onError.bind(this))
    this.#server.on('message', this.#onMessage.bind(this))
  }

  #onListening() {
    if (this.#logLevel) {
      console.log('Start working')
    }

    for (const peer of this.#peers) {
      if (peer.endpoint) {
        peer.forceHandshake()
      }
    }
  }

  getStat() {}
}

module.exports = Wireguard
