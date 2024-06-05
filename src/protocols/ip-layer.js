const { EventEmitter } = require('events')
const DNSResolver = require('./dns-resolver.js')
const UDPStream = require('./udp-stream.js')
const TCPContainer = require('./tcp-container.js')
const { TCP, UDP } = require('./constants.js')

class IPLayer extends EventEmitter {
  #dnsResolver = /** @type{DNSResolver}*/ null
  #udpStream = /** @type{UDPStream}*/ null
  #tcpContainer = /** @type{TCPContainer} */ null

  #logLevel
  #log

  constructor({ logLevel = 1, log = console.log } = {}) {
    super()

    this.#logLevel = logLevel
    this.#log = log

    this.#dnsResolver = new DNSResolver({ log, logLevel })
    this.#udpStream = new UDPStream({ log, logLevel })
    this.#tcpContainer = new TCPContainer({ log, logLevel })
    this.#dnsResolver.on('DNSResponse', this.#emitIPv4Packet.bind(this))
    this.#udpStream.on('udpMessage', this.#emitIPv4Packet.bind(this))
    this.#tcpContainer.on('tcpMessage', this.#emitIPv4Packet.bind(this))
  }

  #emitIPv4Packet(packet) {
    this.emit('ipv4ToTunnel', packet)
  }

  close() {
    this.#dnsResolver.close()
    this.#udpStream.close()
    this.#tcpContainer.close()
  }

  /**
   * @param {IP4Packet}ip4Packet
   */
  send(ip4Packet) {
    if (ip4Packet.protocol === UDP) {
      const udpMessage = ip4Packet.getUDPMessage()

      if (udpMessage.isDnsRequest()) {
        return this.#dnsResolver.request(ip4Packet, udpMessage)
      }

      return this.#udpStream.send(ip4Packet, udpMessage)
    }

    if (ip4Packet.protocol === TCP) {
      const tcpMessage = ip4Packet.getTCPMessage()

      return this.#tcpContainer.send(ip4Packet, tcpMessage)
    }

    // console.log(`unknown protocol ${ipv4Packet.protocolNum}`, ipv4Packet.payload.toString('hex'))
  }
}

module.exports = IPLayer
