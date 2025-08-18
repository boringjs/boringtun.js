const dgram = require('dgram')
const { EventEmitter } = require('events')
const DNSMessage = require('./dns-message.js')
const IP4Packet = require('./ip4-packet.js')
const { UDP } = require('./constants.js')

const Logger = require('../utils/logger.js')
const TIME_DNS_EXPIRE = 30_000
const GC_INTERVAL = 3_000

class DNSResolver extends EventEmitter {
  #dnsRequestMap = new Map()
  #udpConnectionTimeout = null
  #udpProxySocket = dgram.createSocket('udp4')
  #expireDelta
  #logger = /** @type{Logger}*/ null

  constructor({ logger, expireDelta = TIME_DNS_EXPIRE } = {}) {
    super()
    this.#logger = logger || new Logger()
    this.#udpConnectionTimeout = setInterval(this.#cleanUDPConnections.bind(this), GC_INTERVAL)
    this.#udpProxySocket.on('message', this.#onReceiveDNSMessage.bind(this))
    this.#expireDelta = expireDelta
  }

  #cleanUDPConnections() {
    for (const [id, client] of this.#dnsRequestMap) {
      if (Date.now() > client.expire) {
        this.#dnsRequestMap.delete(id)
      }
    }
  }

  #onReceiveDNSMessage(message, { address, port }) {
    const dns = new DNSMessage(message)
    this.#logger.debug(() => ['receive dns response', dns])

    if (!dns || !dns.valid || !dns.isResponse()) {
      this.#logger.warn(() => 'not valid response')
      return
    }

    const id = dns.id

    if (!this.#dnsRequestMap.has(id)) {
      return
    }
    const client = this.#dnsRequestMap.get(id)
    const packet = new IP4Packet({
      protocol: UDP,
      sourceIP: address,
      sourcePort: port,
      destinationIP: client.sourceIP,
      destinationPort: client.sourcePort,
      ttl: 64,
      identification: 0,
      udpData: message,
    })

    this.#logger.debug('emit dns response')
    this.emit('DNSResponse', packet)
  }

  /**
   * @param {IP4Packet} ip4Packet
   * @param {UDPMessage} udpMessage
   */
  request(ip4Packet, udpMessage) {
    const dns = udpMessage.getDNSMessage()

    if (!dns || !dns.valid || !dns.isRequest()) {
      this.#logger.warn('not valid dns')
      return
    }

    this.#dnsRequestMap.set(dns.id, {
      expire: Date.now() + TIME_DNS_EXPIRE,
      sourcePort: udpMessage.sourcePort,
      sourceIP: ip4Packet.sourceIP,
    })

    this.#logger.debug(
      () => `send request ${udpMessage.destinationIP}:${udpMessage.destinationPort} ${udpMessage.data.length} bytes`,
    )
    this.#udpProxySocket.send(udpMessage.data, udpMessage.destinationPort, udpMessage.destinationIP.toString())
  }

  close() {
    clearInterval(this.#udpConnectionTimeout)
    if (this.#udpProxySocket) {
      this.#udpProxySocket.close()
      this.#udpProxySocket = null
    }
  }
}

module.exports = DNSResolver
