const { EventEmitter } = require('events')
const UDPClient = require('./udp-client.js')
const Logger = require('../utils/logger.js')

class UdpContainer extends EventEmitter {
  #udpClients = /** @type{Map<string, UDPClient>}*/ new Map()
  #udpSocketFactory = null
  #logger

  constructor({ logger = new Logger(), udpSocketFactory }) {
    super()
    this.#logger = logger
    this.#udpSocketFactory = udpSocketFactory
  }

  /**
   * @param {IP4Packet} ip4Packet
   * @param {UDPMessage} udpMessage
   */
  send(ip4Packet, udpMessage) {
    const sourceIP = ip4Packet.sourceIP
    const destinationIP = ip4Packet.destinationIP
    const sourcePort = udpMessage.sourcePort
    const destinationPort = udpMessage.destinationPort

    const hash = `${sourceIP}:${sourcePort}:${destinationIP}:${destinationPort}`

    if (!this.#udpClients.has(hash)) {
      const client = new UDPClient({
        sourceIP,
        sourcePort,
        destinationPort,
        destinationIP,
        logger: this.#logger,
        udpSocketFactory: this.#udpSocketFactory,
      })
      this.#udpClients.set(hash, client)
      client.on('close', this.#udpClients.delete.bind(this.#udpClients, hash))
      client.on('udpMessage', this.emit.bind(this, 'udpMessage'))
    }

    this.#udpClients.get(hash).send(udpMessage.data)
  }

  close() {
    for (const [, client] of this.#udpClients) {
      client.close()
    }
  }
}

module.exports = UdpContainer
