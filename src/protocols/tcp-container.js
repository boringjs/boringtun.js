const TCPStream = require('./tcp-stream.js')
const { TCP } = require('./constants.js')
const { EventEmitter } = require('events')
const Logger = require('../utils/logger.js')

class TCPContainer extends EventEmitter {
  #tcpConnections = /** @type{Map<string, TCPStream>} */ new Map() // Map (maps connection identifiers to TCPStream instances)
  #logger = /** @type{Logger} */ null
  #getTCPSocket

  constructor({ logger, getTCPSocket } = {}) {
    super()
    this.#logger = logger || new Logger()
    this.#getTCPSocket = getTCPSocket
  }

  send(ipv4Packet, tcpMessage) {
    const { sourceIP, destinationIP } = ipv4Packet
    const { sourcePort, destinationPort } = tcpMessage

    const tcpStream = this.#getTCPStream({ sourceIP, destinationIP, sourcePort, destinationPort })

    tcpStream.send(ipv4Packet, tcpMessage)
  }

  #getTCPStreamHash({ sourceIP, destinationIP, sourcePort, destinationPort }) {
    return `${TCP}:${sourceIP}:${sourcePort}:${destinationIP}:${destinationPort}`
  }

  /**
   * @param {IP4Address} sourceIP
   * @param {IP4Address} destinationIP
   * @param {number} sourcePort
   * @param {number} destinationPort
   * @return {TCPStream}
   */
  #getTCPStream({ sourceIP, destinationIP, sourcePort, destinationPort }) {
    const hash = this.#getTCPStreamHash({
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
        getTCPSocket: this.#getTCPSocket,
      })
      this.#tcpConnections.set(hash, tcpStream)

      tcpStream.on('tcpMessage', this.emit.bind(this, 'tcpMessage'))
      tcpStream.once('close', this.#tcpConnections.delete.bind(this.#tcpConnections, hash))
    }

    return this.#tcpConnections.get(hash)
  }

  close() {
    for (const [, tcpStream] of this.#tcpConnections) {
      tcpStream.close()
    }
  }
}

module.exports = TCPContainer
