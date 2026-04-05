const dgram = require('dgram')
const { EventEmitter } = require('events')
const DNSMessage = require('./dns-message.js')
const IP4Packet = require('./ip4-packet.js')
const { UDP } = require('./constants.js')

const TIME_DNS_EXPIRE = 30_000
const GC_INTERVAL = 3_000

const DNS_RESOLVER = '[DNS_RESOLVER]'

class DNSResolver extends EventEmitter {
  #dnsRequestMap = new Map()
  #udpConnectionTimeout = null
  #udpSocket = null
  #udpSocketFactory
  #expireDelta
  #logger = /** @type{Logger}*/ null
  #id = 0
  #peerId = null
  static #requestCounter = Math.floor(Math.random() * 1000)
  static #inc() {
    this.#requestCounter = (this.#requestCounter + 1) % 65535
    return this.#requestCounter
  }

  constructor({ peerId, id, logger, udpSocketFactory = dgram.createSocket, expireDelta = TIME_DNS_EXPIRE } = {}) {
    super()
    this.#id = id
    this.#logger = logger
    this.#udpSocketFactory = udpSocketFactory
    this.#expireDelta = expireDelta
    this.#peerId = peerId
  }

  get id() {
    return this.#id
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

    if (!this.#dnsRequestMap.has(dns.id)) {
      this.#logger.debug(() => {
        const f = `${DNS_RESOLVER}[id-${dns.id}]`
        const msg = dns.parseMessage()
        const trace = `from ${address}:${port}`
        const res = `${msg.questions?.[0].name} -> ${msg.answers.map(({ data }) => data).join(',')}`
        return { f, trace, res }
      })
      return
    }

    const client = this.#dnsRequestMap.get(dns.id)

    this.#logger.debug(() => {
      const f = `${DNS_RESOLVER}[id-${client.originId}]`
      const msg = dns.parseMessage()
      const trace = `${client.sourceIP}:${client.sourcePort} <-> ${client.destinationIP}:${client.destinationPort}`
      const res = `${msg.questions?.[0].name} -> ${msg.answers.map(({ data }) => data).join(',')}`
      return { f, trace, res }
    })

    this.#dnsRequestMap.delete(dns.id)

    dns.id = client.originId
    // todo modify id not with side effect

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
    this.emit('udpMessage', packet)
    // this.emit('DNSResponseParsed', { request: client.initMessage.parseMessage(), response: dns.parseMessage() })
  }

  #checkConnection() {
    if (this.#udpSocket) {
      return
    }
    this.#udpSocket = this.#udpSocketFactory({
      type: 'udp4',
      peerId: this.#peerId,
      sourceIP: null,
      sourcePort: null,
      destinationIP: null,
      destinationPort: null,
    })
    this.#udpConnectionTimeout = setInterval(this.#cleanUDPConnections.bind(this), GC_INTERVAL)
    this.#udpSocket.on('message', this.#onReceiveDNSMessage.bind(this))
  }

  /**
   * @param {IP4Packet} ip4Packet
   * @param {UDPMessage} udpMessage
   */
  send(ip4Packet, udpMessage) {
    const requestDNS = udpMessage.getDNSMessage()

    if (!requestDNS || !requestDNS.valid || !requestDNS.isRequest()) {
      this.#logger.warn(() => {
        return { f: DNS_RESOLVER, msg: 'not valid dns response' }
      })
      return
    }

    this.#checkConnection()

    const sourcePort = udpMessage.sourcePort
    const sourceIP = ip4Packet.sourceIP
    const destinationIP = ip4Packet.destinationIP
    const destinationPort = udpMessage.destinationPort
    const outgoingUDP = udpMessage.copy()
    const mapId = DNSResolver.#inc()
    const originId = requestDNS.id

    if (this.#dnsRequestMap.has(mapId)) {
      this.#logger.warn(() => ({ f: `${DNS_RESOLVER}[id:${mapId}]`, msg: 'request with that number exists' }))
    }

    const outgoingDNS = outgoingUDP.getDNSMessage()

    outgoingDNS.id = mapId

    // todo: this mutate origin udpMessage so make it clear

    this.#dnsRequestMap.set(mapId, {
      requestDNS,
      outgoingDNS,
      originId,
      expire: Date.now() + this.#expireDelta,
      sourcePort,
      sourceIP,
      destinationIP,
      destinationPort,
    })

    // for debug
    this.#logger.ignore(() => {
      const f = `${DNS_RESOLVER}[id-${mapId}]`
      const trace = `${sourceIP}:${sourcePort} <-> ${destinationIP}:${destinationPort}`
      return { f, msg: 'DNS_RESOLVER request', trace }
    })

    this.#udpSocket.send(outgoingUDP.data, destinationPort, destinationIP.toString())
  }

  close() {
    clearInterval(this.#udpConnectionTimeout)
    if (this.#udpSocket) {
      this.#udpSocket.close()
      this.#udpSocket = null
    }
  }
}

module.exports = DNSResolver
