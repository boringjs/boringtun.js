const { EventEmitter } = require('events')
const crypto = require('crypto')
const net = require('net')
const Deque = require('./../utils/deque.js')
const { TCP } = require('./constants.js')
const IP4Packet = require('./ip4-packet.js')
const Logger = require('../utils/logger.js')

const SOCKET_CONNECTION_TIMEOUT = 30000
const DELTA = 1000 // todo rename

class TCPStream extends EventEmitter {
  static #socketCounter = 0
  #sourceIP = null // : String
  #destinationIP = null // : String
  #sourcePort = null // : Integer
  #destinationPort = null // : Integer
  #socket = /** @type{Socket} */ null
  #onSocketDataBind
  #onSocketErrorBind
  #closeBind
  #socketStage = 'new'
  #tcpStage = 'new'
  #connectionTimeout = null
  #sequenceNumberValue = 0
  #acknowledgmentNumberValue = 0
  #packetDeque = new Deque()
  #delta = 0
  #id = 0
  #logger = /** @type{Logger} */ null
  #socketDebugId = TCPStream.#socketCounter++
  /**
   * @param {Object} options
   * @param {string} options.host
   * @param {number} options.port
   * @param {Function} callback
   * @returns {net.Socket}
   */
  #getTCPSocket
  #hash = null

  /**
   * @param {object} options
   * @param {IP4Address} options.sourceIP
   * @param {IP4Address} options.destinationIP
   * @param {number} options.sourcePort
   * @param {number} options.destinationPort
   * @param {string} options.hash
   */
  constructor({
    sourceIP,
    destinationIP,
    sourcePort,
    destinationPort,
    delta = DELTA,
    getTCPSocket = (options, callback) => net.connect(options, callback),
    logger,
    hash,
  }) {
    super()
    this.#hash = hash
    this.#sourceIP = sourceIP
    this.#destinationIP = destinationIP
    this.#sourcePort = sourcePort
    this.#destinationPort = destinationPort
    this.#delta = delta
    this.#getTCPSocket = getTCPSocket
    this.#logger = logger || new Logger()
  }

  set #acknowledgmentNumber(v) {
    this.#acknowledgmentNumberValue = v % 4294967296
  }

  get #acknowledgmentNumber() {
    return this.#acknowledgmentNumberValue
  }

  set #sequenceNumber(v) {
    this.#sequenceNumberValue = v % 4294967296
  }

  get #sequenceNumber() {
    return this.#sequenceNumberValue
  }

  #createTCP(options = {}) {
    this.#id = (this.#id + 1) % 65536
    return new IP4Packet({
      protocol: TCP,
      ipFlags: 0,
      ttl: 64,
      sourceIP: this.#destinationIP,
      destinationIP: this.#sourceIP,
      identification: this.#id,
      sourcePort: this.#destinationPort,
      destinationPort: this.#sourcePort,
      sequenceNumber: this.#sequenceNumber,
      acknowledgmentNumber: this.#acknowledgmentNumber,
      urgentPointer: 0,
      window: 65535, // todo check
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

  #onSocketError(error) {
    if (error.message.includes('ECONNRESET')) {
      this.#emitIp4Packet(this.#createTCP({ RST: true }))
      this.#tcpStage = 'reset'
      this.close()
      this.#emitClose()
      return
    }
    this.#logger.error(() => [`error: "${error.message}" "${error.code}"`, error])
  }

  /**
   * @param {Buffer} data
   */
  #onSocketData(data) {
    this.#logger.debug(() => `data from socket ${this.#socketDebugId}: ${data.length}`)
    let offsetFrom = 0

    while (offsetFrom < data.length) {
      let offsetTo = offsetFrom + this.#delta
      if (offsetTo >= data.length) {
        offsetTo = data.length
      }

      const subData = data.slice(offsetFrom, offsetTo)

      const ip4Packet = this.#createTCP({
        data: subData,
        ACK: true,
        PSH: offsetTo === data.length,
      })

      this.#emitIp4Packet(ip4Packet)

      this.#sequenceNumber += subData.length
      offsetFrom = offsetTo
    }
  }

  /**
   * @param {IP4Packet} ip4Packet
   */
  #emitIp4Packet(ip4Packet) {
    this.emit('ip4Packet', ip4Packet)
  }

  #getRandomSequenceNumber() {
    return crypto.randomBytes(4).readUInt32BE(0)
  }

  #finStage(tcpMessage) {
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
      this.#emitIp4Packet(this.#createTCP({ FIN: true }))
      this.#logger.debug(() => 'grace close connection by server')
      this.#emitClose()
      return
    }

    // client init fin
    if (this.#tcpStage === 'fin_client') {
      this.#acknowledgmentNumber += 1

      this.#logger.debug(() => 'send ack fin')
      this.#emitIp4Packet(this.#createTCP({ ACK: true }))
      // this.#sequenceNumber += 1 // ?
      this.#emitIp4Packet(this.#createTCP({ FIN: true, ACK: true }))
      this.#tcpStage = 'fin_client2'
      return
    }

    if (tcpMessage.ACK && this.#tcpStage === 'fin_client2') {
      this.#logger.debug(() => [
        'grace close by client:',
        this.#acknowledgmentNumber,
        tcpMessage.sequenceNumber,
        this.#sequenceNumber,
        tcpMessage.acknowledgmentNumber,
      ])
      this.#emitClose()
    }
  }

  /**
   * @param {Buffer} data
   * @throws
   */
  #writeDataToSocket() {
    if (!this.#packetDeque.size) {
      return
    }

    if (this.#socketStage !== 'established') {
      this.#logger.debug(() => 'socket is not connected')
      return
    }

    if (!this.#socket?.writable) {
      this.#logger.debug(() => 'socket is not writable')
      return
    }

    while (this.#packetDeque.size) {
      const data = this.#packetDeque.shift().data
      this.#socket.write(data)
    }
  }

  #connect(ipv4Packet) {
    if (this.#socketStage !== 'new') {
      this.#logger.error(() => 'socket is not new')
      return
    }

    this.#socketStage = 'connecting'
    this.#connectionTimeout = setTimeout(this.close.bind(this), SOCKET_CONNECTION_TIMEOUT)

    this.#logger.debug(() => `connecting: ${this.#destinationIP.toString()}:${this.#destinationPort}`)

    const port = this.#destinationPort
    const host = this.#destinationIP.toString()
    this.#socket = this.#getTCPSocket({ host, port }, this.#onSocketConnect.bind(this, ipv4Packet))
    this.#socket.on('data', (this.#onSocketDataBind = this.#onSocketData.bind(this)))
    this.#socket.on('error', (this.#onSocketErrorBind = this.#onSocketError.bind(this)))
    this.#socket.on('close', (this.#closeBind = this.close.bind(this)))
  }

  #onSocketConnect(ip4Packet) {
    clearTimeout(this.#connectionTimeout)
    this.#socketStage = 'established'
    this.#emitIp4Packet(ip4Packet)
    this.#writeDataToSocket()
  }

  #emitClose() {
    this.emit('close')
  }

  /**
   * @param {IP4Packet} ip4Packet
   * @param {TCPMessage} tcpMessage
   */
  send(tcpMessage) {
    if (tcpMessage.RST) {
      this.#logger.debug(() => 'connection reset')
      this.#tcpStage = 'reset'
      this.close()
      this.#emitClose()
      return
    }

    if (this.#tcpStage.includes('fin')) {
      return this.#finStage(tcpMessage)
    }

    if (tcpMessage.FIN) {
      this.#logger.debug(() => `fin client ${this.#socketDebugId}`)
      this.#tcpStage = 'fin_client'
      this.#finStage(tcpMessage)
      this.close()
      return
    }

    if (tcpMessage.SYN) {
      if (this.#tcpStage !== 'new') {
        return
      }

      this.#tcpStage = 'syn'
      this.#sequenceNumber = this.#getRandomSequenceNumber()
      this.#acknowledgmentNumber = tcpMessage.sequenceNumber + 1
      const ipv4TCPSynAckMessage = this.#createTCP({ SYN: true, ACK: true })

      this.#connect(ipv4TCPSynAckMessage)
      return
    }

    if (tcpMessage.ACK && this.#tcpStage === 'syn') {
      this.#tcpStage = 'established'
      // Update acknowledgment number to received sequence + 1
      this.#acknowledgmentNumber = tcpMessage.sequenceNumber + 1
      return
    } // return

    if (tcpMessage.ACK && tcpMessage.data.length === 0) {
      this.#sequenceNumber = tcpMessage.acknowledgmentNumber
      this.#writeDataToSocket()
      return
    } // return

    if (tcpMessage.ACK) {
      this.#packetDeque.push(tcpMessage)
      // Update acknowledgment number to received sequence number (which already includes data length)
      this.#acknowledgmentNumber = tcpMessage.sequenceNumber
      this.#emitIp4Packet(this.#createTCP({ ACK: true }))
    } else {
      this.#logger.debug(() => 'strange socket!!!')
    }

    if (this.#socketStage === 'established') {
      this.#writeDataToSocket()
    }
  }

  close() {
    this.#logger.debug(() => `close socket ${this.#socketDebugId}`)
    if (this.#socket) {
      this.#socket.off('data', this.#onSocketDataBind)
      this.#socket.off('error', this.#onSocketErrorBind)
      this.#socket.off('close', this.#closeBind)
      this.#socket.destroy()
      this.#socket = null
    }

    if (this.#tcpStage === 'established') {
      this.#tcpStage = 'fin_init'
      this.#emitIp4Packet(this.#createTCP({ FIN: true }))
    }
  }
}

module.exports = TCPStream
