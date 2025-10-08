const dgram = require('dgram')
const { EventEmitter } = require('events')
const IP4Address = require('./ip4-address.js')
const IP4Packet = require('./ip4-packet.js')
const { UDP } = require('./constants.js')
const Logger = require('../utils/logger.js')

const EXPIRE_DELTA = 60_000
const TICK_DELTA = 1000

const UDP_CLIENT = '[UDP_CLIENT]'

class UDPClient extends EventEmitter {
  #expire = 0
  #sourceIP = /** @type{IP4Address|null}*/ null
  #sourcePort = 0
  #destinationIP = /** @type{IP4Address|null}*/ null
  #destinationPort = 0
  #udpSocket = /** @type{Socket}*/ null
  #logger = /** @type{Logger}*/ null
  #udpSocketFactory /** @type{function(string): Socket} */ = null // todo fix types
  #tick = null
  #name = ''
  /** @type {number} */
  #id = null
  /** @type {string} */
  #type

  constructor({
    id,
    sourceIP,
    sourcePort,
    destinationIP,
    destinationPort,
    logger,
    udpSocketFactory = dgram.createSocket,
  }) {
    super()
    this.#id = id
    this.#sourceIP = new IP4Address(sourceIP)
    this.#sourcePort = sourcePort
    this.#destinationIP = new IP4Address(destinationIP)
    this.#destinationPort = destinationPort
    this.#udpSocketFactory = dgram.createSocket // udpSocketFactory
    this.#logger = logger || new Logger()
    this.#name = `${this.#type}:${this.#sourceIP}:${this.#sourcePort} -> ${this.#destinationIP}:${this.#destinationPort}`
  }

  get id() {
    return this.#id
  }

  #update() {
    if (!this.#udpSocket) {
      this.#logger.debug(() => `Create ${this.#name}`)
      this.#udpSocket = this.#udpSocketFactory('udp4')
      this.#udpSocket.on('message', this.#onMessage.bind(this))
      this.#tick = setInterval(this.#checkExpire.bind(this), TICK_DELTA)
    }
    this.#expire = Date.now() + EXPIRE_DELTA
  }

  #checkExpire() {
    if (this.#expire < Date.now()) {
      clearInterval(this.#tick)
      this.#tick = null
      this.#logger.debug(() => {
        const f = `${UDP_CLIENT}[id-${this.id}][${this.#name}]`
        const msg = 'Close by timeout'

        return { f, msg }
      })
      this.close()
    }
  }

  send(ip4Packet, udpMessage) {
    this.#update()
    this.#udpSocket.send(udpMessage.data, this.#destinationPort, this.#destinationIP.toString())
  }

  #onMessage(message, { address, port }) {
    if (this.#destinationIP.toString() === address && this.#destinationPort === port) {
      this.#update()

      // this.#logger.debug(() => `Receive udp socket ${this.#name}`) // todo udp debug view

      const packet = new IP4Packet({
        protocol: UDP,
        sourceIP: address,
        sourcePort: port,
        destinationIP: this.sourceIP,
        destinationPort: this.sourcePort,
        ttl: 64,
        identification: 0, // this.#idIncrement(),
        udpData: message,
      })

      this.#emitIPv4Packet(packet)
    }
  }

  #emitIPv4Packet(packet) {
    this.emit('udpMessage', packet)
  }

  get sourceIP() {
    return this.#sourceIP
  }

  get sourcePort() {
    return this.#sourcePort
  }

  close() {
    if (this.#udpSocket) {
      this.#udpSocket.close()
      this.#udpSocket = null
    }
  }
}

module.exports = UDPClient
