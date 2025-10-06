const dgram = require('dgram')
const { EventEmitter } = require('events')
const DNSMessage = require('./dns-message.js')
const IP4Packet = require('./ip4-packet.js')
const { UDP } = require('./constants.js')

const Logger = require('../utils/logger.js')
const TIME_DNS_EXPIRE = 30_000
const GC_INTERVAL = 3_000

const DNS = '[DNS]'

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

    // todo search by address port not only with dns id

    if (!dns || !dns.valid || !dns.isResponse()) {
      this.#logger.warn(() => 'not valid response')
      return
    }

    const id = this.#getHash(dns)

    if (!this.#dnsRequestMap.has(id)) {
      this.#logger.debug(() => {
        const f = `${DNS}[id-${id}]`
        const msg = dns.parseMessage()
        const trace = `from ${client.destinationIP}:${client.destinationPort}`
        const res = `${msg.questions?.[0].name} -> ${msg.answers.map(({ data }) => data).join(',')}`
        return { f, trace, res }
      })
      return
    }

    const client = this.#dnsRequestMap.get(id)

    this.#logger.debug(() => {
      const f = `${DNS}[id-${id}]`
      const msg = dns.parseMessage()
      const trace = `${client.sourceIP}:${client.sourcePort} <-> ${client.destinationIP}:${client.destinationPort}`
      const res = `${msg.questions?.[0].name} -> ${msg.answers.map(({ data }) => data).join(',')}`
      return { f, trace, res }
    })

    this.#dnsRequestMap.delete(id)

    const packet = new IP4Packet({
      protocol: UDP,
      destinationIP: client.sourceIP,
      destinationPort: client.sourcePort,
      sourceIP: client.destinationIP,
      sourcePort: client.destinationPort,
      ttl: 64,
      identification: 0,
      udpData: message,
    })

    // this.#logger.debug('emit dns response')
    this.emit('DNSResponse', packet)
    // this.emit('DNSResponseParsed', { request: client.initMessage.parseMessage(), response: dns.parseMessage() })
  }

  #getHash(dns) {
    const dnsMsg = dns.parseMessage()
    const req = dnsMsg.questions
      .map(({ name }) => name)
      .sort()
      .join(',')
    return `${dns.id}:${req}`
  }

  /**
   * @param {IP4Packet} ip4Packet
   * @param {UDPMessage} udpMessage
   */
  request(ip4Packet, udpMessage) {
    const dns = udpMessage.getDNSMessage()

    if (!dns || !dns.valid || !dns.isRequest()) {
      this.#logger.warn(() => {
        return { f: DNS, msg: 'not valid dns response' }
      })
      return
    }

    const sourcePort = udpMessage.sourcePort
    const sourceIP = ip4Packet.sourceIP
    const destinationIP = ip4Packet.destinationIP
    const destinationPort = udpMessage.destinationPort

    const id = this.#getHash(dns)

    if (this.#dnsRequestMap.has(id)) {
      this.#logger.warn(() => ({ f: `${DNS}[id:${id}]`, msg: 'request with that number exists' }))
    }

    this.#dnsRequestMap.set(id, {
      initMessage: dns,
      expire: Date.now() + this.#expireDelta,
      sourcePort,
      sourceIP,
      destinationIP,
      destinationPort,
    })

    // for debug
    this.#logger.ignore(() => {
      const f = `[DNS][id-${id}]`
      const trace = `${sourceIP}:${sourcePort} <-> ${destinationIP}:${destinationPort}`
      return { f, msg: 'DNS request', trace }
    })

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
