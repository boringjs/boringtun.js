const { EventEmitter } = require('events')
const UDPClient = require('./udp-client.js')

class UDPStream extends EventEmitter {
  #udpClients = /** @type{Map<string, UDPClient>}*/ new Map()
  #log
  #logLevel

  constructor({ log = console.log, logLevel = 1 }) {
    super()
    this.#log = log
    this.#logLevel = logLevel
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

module.exports = UDPStream
