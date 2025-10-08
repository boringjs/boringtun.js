const { EventEmitter } = require('events')
const UDPContainer = require('./udp-container.js')
const TCPContainer = require('./tcp-container.js')
const { TCP, UDP } = require('./constants.js')
const Logger = require('../utils/logger.js')

class IPLayer extends EventEmitter {
  #udpContainer = /** @type{UDPContainer}*/ null
  #tcpContainer = /** @type{TCPContainer} */ null
  #logger = /** @type{Logger}*/ null

  constructor({ logger, tcpSocketFactory, udpSocketFactory } = {}) {
    super()
    this.#logger = logger || new Logger({ logLevel: 0 })
    this.#udpContainer = new UDPContainer({ logger, udpSocketFactory })
    this.#tcpContainer = new TCPContainer({ logger, tcpSocketFactory })
    this.#udpContainer.on('udpMessage', this.#emitIPv4Packet.bind(this))
    this.#tcpContainer.on('ip4Packet', this.#emitIPv4Packet.bind(this))
  }

  /**
   * @param {IP4Packet} ip4Packet
   */
  #emitIPv4Packet(ip4Packet) {
    // this.#logger.debug(() => {
    //   const tcpMsg = ip4Packet.protocol === TCP ? JSON.stringify(ip4Packet.getTCPMessage().debugView(), null, 2) : ''
    //
    //   return `from ip layer (${ip4Packet.protocol}): ${ip4Packet.sourceIP} -> ${ip4Packet.destinationIP} ${tcpMsg}`
    // })

    this.emit('ipv4ToTunnel', ip4Packet)
  }

  close() {
    this.#udpContainer.close()
    this.#tcpContainer.close()
  }

  /**
   * @param {IP4Packet} ip4Packet
   */
  send(ip4Packet) {
    if (ip4Packet.protocol === UDP) {
      const udpMessage = ip4Packet.getUDPMessage()

      return this.#udpContainer.send(ip4Packet, udpMessage)
    }

    if (ip4Packet.protocol === TCP) {
      const tcpMessage = ip4Packet.getTCPMessage()

      return this.#tcpContainer.send(ip4Packet, tcpMessage)
    }

    this.#logger.debug(() => `unknown protocol ${ip4Packet.protocolNum}`, ip4Packet.payload.toString('hex'))
  }
}

module.exports = IPLayer
