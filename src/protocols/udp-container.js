const { EventEmitter } = require('events')
const UDPClient = require('./udp-client.js')
const DNSResolver = require('./dns-resolver.js')

const UDP_CONTAINER = '[UDP_CONTAINER]'

class UdpContainer extends EventEmitter {
  static #idCounter = 0
  #udpClients = /** @type{Map<string, UDPClient|DNSResolver>}*/ new Map()
  #udpSocketFactory = null
  #logger

  constructor({ logger, udpSocketFactory }) {
    super()
    this.#logger = logger
    this.#udpSocketFactory = udpSocketFactory
  }

  #getHash({ type, peerId, sourceIP, sourcePort, destinationIP, destinationPort }) {
    switch (type) {
      case 'dns':
        return `dns-${peerId}`
      case 'raw':
        return `${sourceIP}:${sourcePort}:${destinationIP}:${destinationPort}`
      default:
        throw new Error(`Unknown udp type: ${type}`)
    }
  }

  #checkType({ ip4Packet, udpMessage }) {
    if (
      (udpMessage.destinationPort === 53 && udpMessage.isDnsRequest()) ||
      (udpMessage.sourcePort === 53 && udpMessage.isDnsResponse())
    ) {
      return 'dns'
    }

    return 'raw'
  }

  #createUDP({ peerId, sourceIP, destinationIP, sourcePort, destinationPort, hash, type }) {
    if (this.#udpClients.has(hash)) {
      return
    }

    let client = null

    switch (type) {
      case 'raw':
        client = new UDPClient({
          peerId,
          id: UdpContainer.#idCounter++,
          sourceIP,
          sourcePort,
          destinationPort,
          destinationIP,
          logger: this.#logger,
          udpSocketFactory: this.#udpSocketFactory,
        })
        break
      case 'dns':
        client = new DNSResolver({
          peerId,
          id: UdpContainer.#idCounter++,
          logger: this.#logger,
          udpSocketFactory: this.#udpSocketFactory,
        })
        break
      default:
        throw new Error(`Unknown type ${type}`)
    }

    this.#udpClients.set(hash, client)
    client.on('close', this.#udpClients.delete.bind(this.#udpClients, hash))
    client.on('udpMessage', this.emit.bind(this, 'udpMessage'))

    this.#logger.debug(() => {
      const f = `${UDP_CONTAINER}[id-${client.id}][${type}]`
      const msg = `Create udp(${type}) client. UdpCount: ${this.#udpClients.size}`

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
    const peerId = ip4Packet.peerId

    if (!peerId) {
      this.#logger.debug(() => {
        const f = `${UDP_CONTAINER}[${type}]`
        const msg = 'peerId not found'
        return { f, msg }
      })
    }

    const type = this.#checkType({ ip4Packet, udpMessage })
    const hash = this.#getHash({ peerId, type, sourceIP, sourcePort, destinationIP, destinationPort })

    if (!this.#udpClients.has(hash)) {
      this.#createUDP({
        sourceIP,
        destinationIP,
        sourcePort,
        destinationPort,
        hash,
        type,
      })
    }

    this.#udpClients.get(hash).send(ip4Packet, udpMessage)
  }

  close() {
    for (const [, client] of this.#udpClients) {
      client.close()
    }
  }

  getStats() {
    return {
      activeClients: this.#udpClients.size,
    }
  }
}

module.exports = UdpContainer
