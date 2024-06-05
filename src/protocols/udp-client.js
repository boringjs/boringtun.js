const dgram = require('dgram')
const { EventEmitter } = require('events')
const IP4Address = require('./ip4-address.js')
const IP4Packet = require('./ip4-packet.js')
const { UDP } = require('./constants.js')

const EXPIRE_DELTA = 60_000

class UDPClient extends EventEmitter {
  #expire = 0
  #sourceIP = null
  #sourcePort = 0
  #destinationIP =  null
  #destinationPort =  0
  #udpSocket = /** @type{Socket}*/ null

  constructor({ sourceIP, sourcePort, destinationIP, destinationPort }) {
    super()
    this.#sourceIP = new IP4Address(sourceIP)
    this.#sourcePort = sourcePort
    this.#destinationIP = new IP4Address(destinationIP)
    this.#destinationPort = destinationPort
    this.#udpSocket = dgram.createSocket('udp4')
    this.#udpSocket.on('message', this.#onMessage.bind(this))
  }

  #update() {
    this.#expire = Date.now() + EXPIRE_DELTA
  }

  send(message) {
    this.#update()
    this.#udpSocket.send(message, this.#destinationPort, this.#destinationIP.toString())
  }

  #onMessage(message, { address, port }) {
    if (this.#destinationIP.toString() === address && this.#destinationPort === port) {
      this.#update()

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
    // todo destory socket
  }
}

module.exports = UDPClient
