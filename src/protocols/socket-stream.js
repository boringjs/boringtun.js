const { EventEmitter } = require('events')
const net = require('net')
const Deque = require('./../utils/deque.js')
const { TCP } = require('./constants.js')
const IP4Packet = require('./ip4-packet.js')

const SOCKET_CONNECTION_TIMEOUT = 30000

class SocketStream extends EventEmitter {
  #sourceIP = null // : String
  #destinationIP = null // : String
  #sourcePort = null // : Integer
  #destinationPort = null // : Integer
  #netSocket = /** @type{Socket} */ null
  #onNetSocketReceiveBind
  #onNetSocketErrorBind
  #closeBind
  #socketStage = 'new'
  #tcpStage = 'new'
  #connectionTimeout = null
  #sequenceNumber = 0
  #acknowledgmentNumber = 0
  #packetDeque = new Deque()

  /**
   * @param {object} options
   * @param {IP4Address} options.sourceIP
   * @param {IP4Address} options.destinationIP
   * @param {number} options.sourcePort
   * @param {number} options.destinationPort
   */
  constructor({ sourceIP, destinationIP, sourcePort, destinationPort }) {
    super()
    this.#sourceIP = sourceIP
    this.#destinationIP = destinationIP
    this.#sourcePort = sourcePort
    this.#destinationPort = destinationPort
  }

  #setupListeners() {
    this.#netSocket.on('data', (this.#onNetSocketReceiveBind = this.#onNetSocketReceive.bind(this)))
    this.#netSocket.on('error', (this.#onNetSocketErrorBind = this.#onNetSocketError.bind(this)))
    this.#netSocket.on('close', (this.#closeBind = this.close.bind(this)))
  }

  #onNetSocketError(error) {
    console.log(error)
    // this.emit('error', error)
  }

  /**
   * @param {Buffer} data
   */
  #onNetSocketReceive(data) {
    // console.log('data from socket: ', data.slice(0, 50).toString())
    let offset = 0

    while (offset < data.length) {
      let delta = offset + 1000
      if (delta >= data.length) {
        delta = data.length
      }

      const subData = data.slice(offset, delta)

      const ipPacket = new IP4Packet({
        protocol: 'TCP',
        ipFlags: 0,
        ttl: 64,
        sourceIP: this.#destinationIP,
        destinationIP: this.#sourceIP,
        sourcePort: this.#destinationPort,
        destinationPort: this.#sourcePort,
        sequenceNumber: this.#sequenceNumber,
        acknowledgmentNumber: this.#acknowledgmentNumber,
        urgentPointer: 0,
        data: subData,
        URG: false,
        ACK: true,
        PSH: false,
        RST: false,
        SYN: false,
        FIN: false,
        window: 2052,
      })

      this.emit('tcpMessage', ipPacket)

      this.#sequenceNumber += subData.length
      offset = delta
    }
  }

  #getRandomSequenceNumber() {
    return Math.floor(Math.random() * 10000000) // todo refactor
  }

  #createRespondThatReceivedFiles({ ipv4Packet, tcpMessage }) {
    return new IP4Packet({
      protocol: TCP,
      ipFlags: 0,
      ttl: 64,
      sourceIP: ipv4Packet.destinationIP,
      destinationIP: ipv4Packet.sourceIP,
      sourcePort: tcpMessage.destinationPort,
      destinationPort: tcpMessage.sourcePort,
      sequenceNumber: this.#sequenceNumber,
      acknowledgmentNumber: this.#acknowledgmentNumber,
      urgentPointer: 0,
      options: Buffer.alloc(0),
      data: Buffer.alloc(0),
      // URG: false,
      ACK: true,
      // PSH: false,
      // RST: false,
      // SYN: false,
      // FIN: false,
      window: tcpMessage.window,
    })
  }

  #createTCPMessage(options = {}) {
    return new IP4Packet({
      protocol: TCP,
      ipFlags: 0,
      ttl: 64,
      sourceIP: this.#destinationIP,
      destinationIP: this.#sourceIP,
      sourcePort: this.#destinationPort,
      destinationPort: this.#sourcePort,
      sequenceNumber: this.#sequenceNumber,
      acknowledgmentNumber: this.#acknowledgmentNumber,
      urgentPointer: 0,
      window: 3000, // todo check
      options: Buffer.alloc(0),
      data: Buffer.alloc(0),
      URG: false,
      ACK: false,
      PSH: false,
      RST: false,
      SYN: false,
      FIN: false,
      ...options,
    })
  }

  #createFinAckMessage({ ipv4Packet, tcpMessage }) {
    return new IP4Packet({
      protocol: TCP,
      ipFlags: 0,
      ttl: 64,
      sourceIP: ipv4Packet.destinationIP,
      destinationIP: ipv4Packet.sourceIP,
      sourcePort: tcpMessage.destinationPort,
      destinationPort: tcpMessage.sourcePort,
      sequenceNumber: this.#sequenceNumber,
      acknowledgmentNumber: this.#acknowledgmentNumber,
      urgentPointer: 0,
      options: Buffer.alloc(0),
      data: Buffer.alloc(0),
      // URG: false,
      ACK: true,
      // PSH: false,
      // RST: false,
      // SYN: false,
      FIN: true,
      window: tcpMessage.window,
    })
  }

  #emitMessage(ipv4Packet) {
    this.emit('tcpMessage', ipv4Packet)
  }

  #finStage({ ipv4Packet, tcpMessage } = {}) {
    // server init fin
    if (this.#tcpStage === 'connected') {
      this.#tcpStage = 'fin_init'
      this.#emitMessage(this.#createTCPMessage({ FIN: true }))
      return
    }

    if (!tcpMessage) {
      return
    }

    // wait for ack from client
    if (
      this.#tcpStage === 'fin_init' &&
      tcpMessage.ACK &&
      tcpMessage.acknowledgmentNumber === this.#sequenceNumber + 1
    ) {
      this.#tcpStage = 'fin_ack'
      this.#sequenceNumber += 1
      return
    }

    // wait fin from client
    if (
      this.#tcpStage === 'fin_ack' &&
      tcpMessage.FIN &&
      this.#acknowledgmentNumber + 1 === tcpMessage.sequenceNumber
    ) {
      this.#tcpStage = 'fin_ack'
      this.#acknowledgmentNumber += 2
      this.#emitMessage(this.#createTCPMessage({ FIN: true }))
      console.log('grace close connection by server')
      this.emit('close')
      return
    }

    // client init fin
    if (this.#tcpStage === 'fin_client') {
      this.#acknowledgmentNumber += 1
      this.#emitMessage(this.#createTCPMessage({ ACK: true }))
      this.#sequenceNumber += 1
      this.#emitMessage(this.#createTCPMessage({ FIN: true }))
      this.#tcpStage = 'fin_client2'
      return
    }

    if (
      tcpMessage.ACK &&
      this.#tcpStage === 'fin_client2' &&
      tcpMessage.sequenceNumber === this.#acknowledgmentNumber + 1 &&
      tcpMessage.acknowledgmentNumber === this.#sequenceNumber + 1
    ) {
      console.log('grace close connection by client')
      this.emit('close')
    }
  }

  /**
   * @param {IPv4Packet} ipv4Packet
   * @param {TCPMessage} tcpMessage
   */
  send({ ipv4Packet, tcpMessage }) {
    if (this.#tcpStage.includes('fin')) {
      return this.#finStage({ ipv4Packet, tcpMessage })
    }

    if (tcpMessage.FIN) {
      this.#tcpStage = 'fin_client'
      return this.#finStage({ ipv4Packet, tcpMessage })
    }

    if (tcpMessage.RST) {
      console.log('connection reset')
      this.#tcpStage = 'reset'
      this.close()
      this.emit('close')
      return
    }

    if (tcpMessage.SYN) {
      if (this.#tcpStage !== 'new') {
        return
      }

      this.#tcpStage = 'syn'
      this.#sequenceNumber = this.#getRandomSequenceNumber()
      this.#acknowledgmentNumber = tcpMessage.sequenceNumber + 1
      const ipv4TCPSynAckMessage = this.#createSynAckMessage({ ipv4Packet, tcpMessage })
      this.emit('tcpMessage', ipv4TCPSynAckMessage)
      // console.log(`${this.#destinationIP} syn ack`)
      return
    } // return

    if (tcpMessage.ACK && this.#tcpStage === 'syn') {
      this.#tcpStage = 'established'
      // console.log(`tcp socket ${this.#destinationIP} connection established`)
      this.#connect()

      this.#acknowledgmentNumber = tcpMessage.sequenceNumber
      this.#sequenceNumber = tcpMessage.acknowledgmentNumber // todo check
      return
    } // return

    if (tcpMessage.ACK && tcpMessage.data.length === 0) {
      // console.log('skip ack message from client')
      return
    } // return

    if (tcpMessage.ACK) {
      this.#packetDeque.push(tcpMessage)
      this.#acknowledgmentNumber += tcpMessage.data.length
      const respond = this.#createRespondThatReceivedFiles({ ipv4Packet, tcpMessage })
      this.emit('tcpMessage', respond)
    } else {
      console.log('strange socket!!!')
    }

    if (this.#socketStage === 'connected') {
      this.#writeDataToSocket()
    }
  }

  #createSynAckMessage({ ipv4Packet, tcpMessage }) {
    return new IP4Packet({
      protocol: TCP,
      ipFlags: 0,
      ttl: 64,
      sourceIP: ipv4Packet.destinationIP,
      destinationIP: ipv4Packet.sourceIP,
      sourcePort: tcpMessage.destinationPort,
      destinationPort: tcpMessage.sourcePort,
      sequenceNumber: this.#sequenceNumber,
      acknowledgmentNumber: this.#acknowledgmentNumber,
      urgentPointer: 0,
      options: Buffer.alloc(0),
      data: Buffer.alloc(0),
      // URG: false,
      ACK: true,
      // PSH: false,
      // RST: false,
      SYN: true,
      // FIN: false,
      window: tcpMessage.window,
    })
  }

  /**
   * @param {Buffer} data
   * @throws
   */
  #writeDataToSocket() {
    if (this.#socketStage !== 'connected') {
      console.log('socket is not connected')
      return
    }

    if (!this.#netSocket?.writable) {
      console.log('socket is not writable')
      return
    }

    while (this.#packetDeque.size) {
      const packet = this.#packetDeque.shift()
      const data = packet.data
      if (data.length) {
        this.#netSocket.write(data)
      }
    }
  }

  #connect() {
    if (this.#socketStage !== 'new') {
      console.error('socket is not new')
      return
    }

    this.#socketStage = 'connecting'
    this.#connectionTimeout = setTimeout(this.close.bind(this), SOCKET_CONNECTION_TIMEOUT)

    console.log(`connecting: ${this.#destinationIP.toString()}:${this.#destinationPort}`)

    const port = this.#destinationPort
    const host = this.#destinationIP.toString()
    this.#netSocket = net.connect({ host, port }, this.#onSocketConnect.bind(this))
    this.#setupListeners()
  }

  #onSocketConnect() {
    clearTimeout(this.#connectionTimeout)
    this.#socketStage = 'connected'
    this.#writeDataToSocket()
  }

  close() {
    if (this.#netSocket) {
      this.#netSocket.off('data', this.#onNetSocketReceiveBind)
      this.#netSocket.off('error', this.#onNetSocketErrorBind)
      this.#netSocket.off('close', this.#closeBind)
      this.#netSocket.destroy()
      this.#netSocket = null
    }

    if (this.#tcpStage === 'connected') {
      this.#finStage()
    }
  }
}

module.exports = SocketStream
