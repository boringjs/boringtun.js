const dgram = require('dgram')
const { EventEmitter } = require('events')
const DNSMessage = require('./dns-message.js')
const IP4Packet = require('./ip4-packet.js')
const { UDP } = require('./constants.js')

const TIME_DNS_EXPIRE = 30_000
const GC_INTERVAL = 3_000

class DNSResolver extends EventEmitter {
  #dnsRequestMap = new Map()
  #udpConnectionTimeout = null
  #udpProxySocket = dgram.createSocket('udp4')
  #expireDelta
  #logLevel
  #log

  constructor({ logLevel = 1, log = console.log, expireDelta = TIME_DNS_EXPIRE } = {}) {
    super()
    this.#logLevel = logLevel
    this.#log = log
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
    console.log('receive dns reponse', dns)

    if (!dns || !dns.valid || !dns.isResponse()) {
      console.log('not valid response')
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

    console.log('emit dns response')
    this.emit('DNSResponse', packet)
  }

  /**
   * @param {IP4Packet} ip4Packet
   * @param {UDPMessage} udpMessage
   */
  request(ip4Packet, udpMessage) {
    const dns = udpMessage.getDNSMessage()

    if (!dns || !dns.valid || !dns.isRequest()) {
      console.log('not valid dns')
      return
    }

    this.#dnsRequestMap.set(dns.id, {
      expire: Date.now() + TIME_DNS_EXPIRE,
      sourcePort: udpMessage.sourcePort,
      sourceIP: ip4Packet.sourceIP,
    })

    console.log('send request')
    this.#udpProxySocket.send(udpMessage.data, udpMessage.destinationPort, udpMessage.destinationIP.toString())
  }

  close() {
    clearInterval(this.#udpConnectionTimeout)
    // destory socket
  }
}

module.exports = DNSResolver
