const TCPStream = require('./tcp-stream.js')
const { TCP } = require('./constants.js')
const { EventEmitter } = require('events')
const Logger = require('../utils/logger.js')

class TCPContainer extends EventEmitter {
  #tcpConnections = /** @type{Map<string, TCPStream>} */ new Map() // Map (maps connection identifiers to TCPStream instances)
  #logger = /** @type{Logger} */ null
  #tcpSocketFactory
  #socketCounter = 0

  constructor({ logger, tcpSocketFactory } = {}) {
    super()
    this.#logger = logger || new Logger()
    this.#tcpSocketFactory = tcpSocketFactory
  }

  #socketInc() {
    return this.#socketCounter++
  }

  send(ipv4Packet, tcpMessage) {
    const { sourceIP, destinationIP, peerId } = ipv4Packet
    const { sourcePort, destinationPort } = tcpMessage

    const tcpStream = this.#getTCPStream({ peerId, sourceIP, destinationIP, sourcePort, destinationPort })

    tcpStream.send(tcpMessage)
  }

  // peerId is part of the hash so two distinct peers that happen to overlap
  // sourceIP:sourcePort:destIP:destPort (rare but possible across NATed peers)
  // can never alias into the same TCPStream.
  #getTCPStreamHash({ peerId, sourceIP, destinationIP, sourcePort, destinationPort }) {
    return `${TCP}:${peerId || ''}:${sourceIP}:${sourcePort}:${destinationIP}:${destinationPort}`
  }

  /**
   * @param {IP4Address} sourceIP
   * @param {IP4Address} destinationIP
   * @param {number} sourcePort
   * @param {number} destinationPort
   * @return {TCPStream}
   */
  #getTCPStream({ peerId, sourceIP, destinationIP, sourcePort, destinationPort }) {
    const hash = this.#getTCPStreamHash({
      peerId,
      sourceIP,
      sourcePort,
      destinationIP,
      destinationPort,
    })

    if (!this.#tcpConnections.has(hash)) {
      const tcpStream = new TCPStream({
        sourceIP,
        destinationIP,
        sourcePort,
        destinationPort,
        logger: this.#logger,
        tcpSocketFactory: this.#tcpSocketFactory,
        socketId: this.#socketInc(),
      })
      this.#tcpConnections.set(hash, tcpStream)

      tcpStream.on('ip4Packet', this.#onIp4Packet.bind(this))
      tcpStream.once('close', this.#tcpConnections.delete.bind(this.#tcpConnections, hash))
    }

    return this.#tcpConnections.get(hash)
  }

  #onIp4Packet(ip4Packet) {
    this.emit('ip4Packet', ip4Packet)
  }

  close() {
    for (const tcpStream of this.#tcpConnections.values()) {
      tcpStream.close()
    }
  }

  getStats() {
    return {
      activeConnections: this.#tcpConnections.size,
    }
  }
}

module.exports = TCPContainer
