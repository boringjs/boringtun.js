const { EventEmitter } = require('events')
const SocketStream = require('./socket-stream.js')
const IPv4Packet = require('./ip4-packet.js')
const UDPClient = require('./udp-client.js')
const IP4Packet = require('./ip4-packet.js')
const { TCP, UDP } = require('./constants.js')
const dgram = require('dgram')

class IPLayer extends EventEmitter {
  #tcpConnections = new Map() // Map (maps connection identifiers to SocketStream instances)
  #udpClients = new Map() // todo gc
  #udpConnectionTimeout = null
  #index = 0
  #udpProxySocket = dgram.createSocket('udp4')
  #dnsRequestMap = new Map()
  #logLevel
  #log

  constructor({ logLevel = 1, log = console.log } = {}) {
    super()

    this.#udpConnectionTimeout = setInterval(this.cleanUDPConnections.bind(this), 3000)
    this.#udpProxySocket.on('message', this.#onReceiveUDPMessage.bind(this))
    this.#logLevel = logLevel
    this.#log = log
  }

  cleanUDPConnections() {
    // for(const [])
    // console.log('size: ', this.#udpClients.size)
    // for (const [hash, udpConnection] of this.#udpClients) {
    //   if (Date.now() - this.lastUsage > 5000) {
    //     udpConnection.close()
    //     this.#udpConnections.delete(hash)
    //   }
    // }
  }

  close() {
    clearInterval(this.#udpConnectionTimeout)
  }

  #getHash({ protocol, ip, port }) {
    return `${protocol}:${ip}:${port}`
  }

  #setUDPClient(udp) {
    const { sourceIP, sourcePort, destinationIP, destinationPort } = udp
    const targetHash = this.#getHash({ protocol: UDP, port: destinationPort, ip: destinationIP })
    if (!this.#udpClients.has(targetHash)) {
      this.#udpClients.set(targetHash, new Map())
    }

    const clients = this.#udpClients.get(targetHash)
    const clientHash = this.#getHash({ protocol: UDP, port: sourcePort, ip: sourceIP })

    if (clients.has(clientHash)) {
      return
    }

    clients.set(clientHash, new UDPClient({ sourceIP, sourcePort }))
  }

  #getUDPClients({ message, destinationIP, destinationPort }) {
    const isDNS = message.length >= 12 && destinationPort === 53 && (message[2] & 0x80) === 1
    const protocol = isDNS ? 'DNS' : UDP
    const hash = isDNS ? message.readUInt16BE(0) : 0
    const targetHash = this.#getHash({ hash, protocol, port: destinationPort, ip: destinationIP })
    if (!this.#udpClients.has(targetHash)) {
      return new Map()
    }

    return this.#udpClients.get(targetHash)
  }

  #idIncrement() {
    return this.#index++
  }

  #onReceiveUDPMessage(message, { address, port }) {
    const isDNS = message.length >= 12 && port === 53 && (message[2] & 0x80) === 0x80
    const packets = []

    if (isDNS) {
      const transactionId = `${address}${port}${message.readUInt16BE(0)}`
      if (this.#dnsRequestMap.has(transactionId)) {
        const client = this.#dnsRequestMap.get(transactionId)
        packets.push(
          new IP4Packet({
            protocol: UDP,
            sourceIP: address,
            sourcePort: port,
            destinationIP: client.sourceIP,
            destinationPort: client.sourcePort,
            ttl: 64,
            identification: 0, // this.#idIncrement(),
            udpData: message,
          }),
        )
      }
    } else {
      const clients = this.#getUDPClients({ message, destinationIP: address, destinationPort: port })

      for (const [, client] of clients) {
        packets.push(
          new IP4Packet({
            protocol: UDP,
            sourceIP: address,
            sourcePort: port,
            destinationIP: client.sourceIP,
            destinationPort: client.sourcePort,
            ttl: 64,
            identification: 0, // this.#idIncrement(),
            udpData: message,
          }),
        )
      }
    }

    for (const packet of packets) {
      this.emit('ipv4ToTunnel', packet)
    }
  }

  receivePacket(ipv4Packet, data) {
    if (ipv4Packet.protocol === UDP) {
      return this.#receiveUDPPacket(ipv4Packet)
    }

    if (ipv4Packet.protocol === TCP) {
      const tcpMessage = ipv4Packet.getTCPMessage()

      if (this.#logLevel > 3) {
        console.log(`     tcp ${tcpMessage.destinationPort}: ${data.toString('hex')}`)
      }
      return this.#receiveTCPPacket(ipv4Packet, tcpMessage)
    }

    // console.log(`unknown protocol ${ipv4Packet.protocolNum}`, ipv4Packet.payload.toString('hex'))
  }

  #receiveUDPPacket(ipv4Packet) {
    const udp = ipv4Packet.getUDPMessage()
    const { sourceIP, destinationIP } = ipv4Packet
    const { sourcePort, destinationPort } = udp
    console.log(`udp: ${sourceIP}:${sourcePort} -> ${destinationIP}:${destinationPort}`)

    if (udp.isDnsRequest()) {
      const transactionId = `${destinationIP}${destinationPort}${udp.data.readUInt16BE(0)}`
      this.#dnsRequestMap.set(transactionId, new UDPClient({ sourcePort, sourceIP }))
    } else {
      this.#setUDPClient(udp)
    }

    this.#udpProxySocket.send(udp.data, udp.destinationPort, udp.destinationIP.toString())
  }

  #receiveTCPPacket(ipv4Packet, tcpMessage) {
    const { sourceIP, destinationIP } = ipv4Packet
    const { sourcePort, destinationPort } = tcpMessage

    const socketStream = this.#getSocketStream({ sourceIP, destinationIP, sourcePort, destinationPort })

    socketStream.send({ ipv4Packet, tcpMessage })
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

      socketStream.on('ipv4ToTunnel', this.#onSendToTunnel.bind(this))
      socketStream.once('close', this.#tcpConnections.delete.bind(this.#tcpConnections, hash))
    }

    return this.#tcpConnections.get(hash)
  }

  #onSendToTunnel(ipv4Packet) {
    this.emit('ipv4ToTunnel', ipv4Packet)
  }
}

module.exports = IPLayer
