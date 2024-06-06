const SocketStream = require('./socket-stream.js')
const { TCP } = require('./constants.js')
const { EventEmitter } = require('events')

class TCPContainer extends EventEmitter {
  #tcpConnections = /** @type{Map<string, SocketStream>} */ new Map() // Map (maps connection identifiers to SocketStream instances)
  #log
  #logLevel

  constructor({ log = console.log, logLevel = 1 } = {}) {
    super()

    this.#log = log
    this.#logLevel = logLevel
  }

  send(ipv4Packet, tcpMessage) {
    const { sourceIP, destinationIP } = ipv4Packet
    const { sourcePort, destinationPort } = tcpMessage

    const socketStream = this.#getSocketStream({ sourceIP, destinationIP, sourcePort, destinationPort })

    socketStream.send(ipv4Packet, tcpMessage)
  }

  #getSocketStreamHash({ sourceIP, destinationIP, sourcePort, destinationPort }) {
    return `${TCP}:${sourceIP}:${sourcePort}:${destinationIP}:${destinationPort}`
  }

  /**
   * @param {IP4Address} sourceIP
   * @param {IP4Address} destinationIP
   * @param {number} sourcePort
   * @param {number} destinationPort
   * @return {SocketStream}
   */
  #getSocketStream({ sourceIP, destinationIP, sourcePort, destinationPort }) {
    const hash = this.#getSocketStreamHash({
      sourceIP,
      sourcePort,
      destinationIP,
      destinationPort,
    })

    if (!this.#tcpConnections.has(hash)) {
      const socketStream = new SocketStream({ sourceIP, destinationIP, sourcePort, destinationPort })
      this.#tcpConnections.set(hash, socketStream)

      socketStream.on('tcpMessage', this.emit.bind(this, 'tcpMessage'))
      socketStream.once('close', this.#tcpConnections.delete.bind(this.#tcpConnections, hash))
    }

    return this.#tcpConnections.get(hash)
  }

  close() {
    for (const [, socketStream] of this.#tcpConnections) {
      socketStream.close()
    }
  }
}

module.exports = TCPContainer
