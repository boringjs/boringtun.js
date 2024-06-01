const dgram = require('dgram')
const { EventEmitter } = require('events')
const IPLayer = require('./protocols/ip-layer.js')
const { checkValidKey, getPublicKeyFrom } = require('./tunnel.js')
const Peer = require('./peer.js')
const IP4Address = require('./protocols/ip4-address.js')

class Wireguard extends EventEmitter {
  #ipLayer = new IPLayer()
  #privateKey = ''
  #publicKey = ''
  #listenPort = 0
  #server /** @type {Socket}*/ = dgram.createSocket('udp4')
  #ip = new IP4Address(0)
  #testPeer = null // todo remove
  #mapPeerIpToPeer = new Map()
  #mapEndpointIpToPeer = new Map()
  #index = 1

  constructor({ privateKey, listenPort, ip }) {
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
    this.#ip = new IP4Address(ip)
    this.#createServerListeners()
    this.#ipLayer.on('ipv4ToTunnel', this.onMessageFromIPLayer.bind(this))
  }

  onMessageFromIPLayer(ipv4Packet) {
    const peer = this.#getPeerByMessage({}) // todo
    const message = ipv4Packet.toBuffer()
    if (ipv4Packet.protocol === 'TCP') {
      console.log('to tunnel:', message.toString('hex'))
    }
    peer.write(message)
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

  /**
   * @param {Buffer} msg
   * @param {IP4Address|string} address
   * @param {number} port
   * @return {Peer}
   */
  #getPeerByMessage({ msg, endpoint }) {
    return this.#testPeer
  }

  #onWriteToTunnel({ address, port, data }) {
    this.#server.send(data, port, address, (error) => (error ? console.error(`Error onsend to client${error}`) : null))
  }

  #onWriteToIPv4({ peerIp, data }) {
    this.#ipLayer.receivePacket({ peerIp, data })
  }

  /**
   * @param {Buffer} msg
   * @param {{address: string, port: number}}
   */
  #onMessage(msg, { address, port }) {
    const endpoint = `${address}:${port}`

    // routing
    const peer = this.#getPeerByMessage({ msg, endpoint })

    if (!peer) {
      return
    }

    if (peer.endpoint && this.#mapEndpointIpToPeer.get(peer.endpoint) !== peer) {
      this.#mapEndpointIpToPeer.delete(peer.endpoint)
    }

    peer.endpointPort = port
    peer.endpointAddress = address

    this.#mapEndpointIpToPeer.set(endpoint, peer)

    peer.read(msg)
  }

  /**
   * @param {Buffer} data
   */
  #onError(data) {
    console.log(data)
    // todo
  }

  #createServerListeners() {
    this.#server.on('error', this.#onError.bind(this))
    this.#server.on('message', this.#onMessage.bind(this))
  }

  addPeer({ publicKey, ip, keepAlive = 25, endpoint }) {
    const [endpointAddress, endpointPort] = (endpoint || '').split(':')

    const peer = new Peer({
      privateServerKey: this.privateKey,
      publicKey,
      ip,
      keepAlive,
      index: this.#index++,
      endpointPort,
      endpointAddress,
    })

    this.#mapPeerIpToPeer.set(ip, peer)

    if (peer.endpoint) {
      this.#mapEndpointIpToPeer.set(endpoint, peer)
      // todo forcehandshake
    }

    peer.on('writeToTunnel', ({ address, port, data }) => {
      this.#onWriteToTunnel({ address, port, data })
    })

    peer.on('writeToIp4Layer', ({ peerIp, data }) => {
      this.#onWriteToIPv4({ peerIp, data })
    })

    this.#testPeer = peer // todo: this.testTunnel.on('data', () => {})

    return this
  }

  #onListening() {
    console.log('start working')
  }

  listen() {
    this.#server.bind(this.#listenPort, this.#onListening.bind(this))
  }
}

module.exports = Wireguard
