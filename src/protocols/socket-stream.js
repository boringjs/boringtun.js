const net = require('net')
const { EventEmitter } = require('events')
const Deque = require('./../utils/deque.js')
const { TCP } = require('./constants.js')
const IP4Packet = require('./ip4-packet.js')

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
    // this.#netSocket.on('close', (this.#closeBind = this.close.bind(this)))
  }

  #onNetSocketError(error) {
    console.log(error)
    // this.emit('error', error)
  }

  /**
   * @param {Buffer} data
   */
  #onNetSocketReceive(data) {
    console.log('data from socket: ', data.slice(0, 50).toString())
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

      this.emit('ipv4ToTunnel', ipPacket)

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

  /**
   * @param {IPv4Packet} ipv4Packet
   * @param {TCPMessage} tcpMessage
   */
  send({ ipv4Packet, tcpMessage }) {
    if (tcpMessage.SYN) {
      if (this.#tcpStage !== 'new') {
        return
      }

      this.#tcpStage = 'syn'
      this.#sequenceNumber = this.#getRandomSequenceNumber()
      this.#acknowledgmentNumber = tcpMessage.sequenceNumber + 1
      const ipv4TCPSynAckMessage = this.#createSynAckMessage({ ipv4Packet, tcpMessage })
      this.emit('ipv4ToTunnel', ipv4TCPSynAckMessage)
      console.log(`${this.#destinationIP} syn ack`)
      return
    }

    if (tcpMessage.ACK && this.#tcpStage === 'syn') {
      this.#tcpStage = 'established'
      console.log(`tcp socket ${this.#destinationIP} connection established`)
      this.#connect()

      this.#acknowledgmentNumber = tcpMessage.sequenceNumber
      this.#sequenceNumber = tcpMessage.acknowledgmentNumber // todo check
      return
    }

    if (tcpMessage.FIN) {
      // todo
      return
    }

    if (tcpMessage.ACK && tcpMessage.data.length === 0) {
      console.log('skip ack message from client')
      return
    }

    if (tcpMessage.ACK) {
      this.#packetDeque.push(tcpMessage)
      this.#acknowledgmentNumber += tcpMessage.data.length
      const respond = this.#createRespondThatReceivedFiles({ ipv4Packet, tcpMessage })
      this.emit('ipv4ToTunnel', respond)
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
      console.log(`write to socket ${data.length}`)
      if (data.length) {
        this.#netSocket.write(data)
      }
    }
  }

  #connect() {
    if (this.#socketStage !== 'new') {
      console.log('socket is not new')
      return
    }

    console.log('try to connect')
    this.#socketStage = 'connecting'
    return new Promise(this.#connectPromiseHandler.bind(this))
  }

  #connectPromiseHandler(resolve, reject) {
    this.#connectionTimeout = setTimeout(reject, 30000, new Error('Cannot connect to target'))
    console.log(`try to connect ${this.#destinationIP.toString()}:${this.#destinationPort}`)
    this.#netSocket = net.connect(
      { port: this.#destinationPort, host: this.#destinationIP.toString() },
      this.#onSocketConnect.bind(this, resolve),
    )
    this.#setupListeners()
  }

  #onSocketConnect(resolve) {
    console.log('tcp socket connected')
    clearTimeout(this.#connectionTimeout)
    this.#socketStage = 'connected'
    this.#writeDataToSocket()
    resolve()
  }

  #sendFIN() {}

  // : Closes the TCP connection.
  close() {
    console.log('close all')
    this.#netSocket.off('data', this.#onNetSocketReceiveBind)
    this.#netSocket.off('error', this.#onNetSocketErrorBind)
    this.#netSocket.off('close', this.#closeBind)

    if (this.#tcpStage === 'connected') {
      this.#tcpStage = 'fin1'
      this.#sendFIN()
    }

    // this.#netSocket.close()
    this.#netSocket.destroy()
    this.#netSocket = null

    this.emit('close')
    // todo emit ipv4 FIN packet
  }
}

module.exports = SocketStream
