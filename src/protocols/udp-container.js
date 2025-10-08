const { EventEmitter } = require('events')
const UDPClient = require('./udp-client.js')
const DNSResolver = require('./dns-resolver.js')

const UDP_CONTAINER = 'UDP_CONTAINER'
const DNS = 'DNS'

class UdpContainer extends EventEmitter {
  static #idCounter = 0
  #udpClients = /** @type{Map<string, UDPClient|DNSResolver>}*/ new Map()
  #udpSocketFactory = null
  #logger

  constructor({ logger, udpSocketFactory }) {
    super()
    this.#logger = logger
    this.#udpSocketFactory = udpSocketFactory
    this.#createDNS()
  }

  #getHash({ ipv4Packet, udpMessage, sourceIP, sourcePort, destinationIP, destinationPort }) {
    if (this.#isDNSMessage(ipv4Packet, udpMessage)) {
      return 'dns'
    }

    return `${sourceIP}:${sourcePort}:${destinationIP}:${destinationPort}`
  }

  #isDNSMessage(ip4Packet, udpMessage) {
    return (
      (udpMessage.destinationPort === 53 && udpMessage.isDnsRequest()) ||
      (udpMessage.sourcePort === 53 && udpMessage.isDnsResponse())
    )
  }

  #createDNS() {
    if (this.#udpClients.has('dns')) {
      return
    }
    const client = new DNSResolver({
      id: UdpContainer.#idCounter++,
      logger: this.#logger,
      udpSocketFactory: this.#udpSocketFactory,
    })

    this.#udpClients.set('dns', client)
    client.on('close', this.#udpClients.delete.bind(this.#udpClients, 'dns'))
    client.on('udpMessage', this.emit.bind(this, 'udpMessage'))

    this.#logger.debug(() => {
      const f = `${UDP_CONTAINER}[id-${client.id}}][dns]`
      const msg = `Create Dns resolver.`

      return { f, msg }
    })
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

    const hash = this.#getHash({ udpMessage, sourceIP, sourcePort, destinationIP })

    if (!this.#udpClients.has(hash)) {
      const client = new UDPClient({
        id: UdpContainer.#idCounter++,
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

      this.#logger.debug(() => {
        const f = `${UDP_CONTAINER}[id-${client.id}}][udp]`
        const msg = `Create UdpClient. UdpCount: ${this.#udpClients.size}`

        return { f, msg }
      })
    }

    this.#udpClients.get(hash).send(ip4Packet, udpMessage)
  }

  close() {
    for (const [, client] of this.#udpClients) {
      client.close()
    }
  }
}

module.exports = UdpContainer
