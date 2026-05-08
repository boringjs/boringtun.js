const { EventEmitter } = require('events')
const crypto = require('crypto')
const net = require('net')
const Deque = require('./../utils/deque.js')
const { TCP } = require('./constants.js')
const IP4Packet = require('./ip4-packet.js')
const Logger = require('../utils/logger.js')

const SOCKET_CONNECTION_TIMEOUT = 30000
const FIN_HANDSHAKE_TIMEOUT = 30000
const DELTA = 1000 // todo rename
const TCP_STREAM = '[TCP_STREAM]'

class TCPStream extends EventEmitter {
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
  #rcvNxt = null // next peer-seq we expect; advances only on in-order data
  #pendingSegments = new Map() // seq -> data, segments arrived ahead of rcvNxt
  #writeQueue = [] // in-order chunks waiting for the upstream socket to be writable
  #sendQueue = new Deque()
  #peerWindow = 65535
  #peerLastAck = null
  #paused = false
  #finTimeout = null
  #delta = 0
  #id = 0
  #logger = /** @type{Logger} */ null
  #socketId = -1
  /**
   * @param {Object} options
   * @param {string} options.host
   * @param {number} options.port
   * @param {Function} callback
   * @returns {net.Socket}
   */
  #tcpSocketFactory
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
    tcpSocketFactory = ({ socketId, sourceIP, sourcePort, ...options }, callback) => net.connect(options, callback),
    logger,
    hash,
    socketId,
  }) {
    super()
    this.#hash = hash
    this.#sourceIP = sourceIP
    this.#destinationIP = destinationIP
    this.#sourcePort = sourcePort
    this.#destinationPort = destinationPort
    this.#delta = delta
    this.#tcpSocketFactory = tcpSocketFactory
    this.#logger = logger || new Logger()
    this.#socketId = socketId
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
    this.#logger.error(() => ({
      f: `${TCP_STREAM}[id-${this.#socketId}]`,
      ip: this.#destinationIP.toString(),
      error: `error ${error.code}: ${error.message}`,
    }))
  }

  /**
   * @param {Buffer} data
   */
  #onSocketData(data) {
    if (data.length === 0) return
    this.#sendQueue.push(data)
    this.#flushSendQueue()
  }

  /**
   * Drain queued upstream bytes into IP4 packets, but respect the peer's
   * advertised receive window. When the peer's window is full, pause the
   * upstream socket and resume when an ACK frees space.
   */
  #flushSendQueue() {
    while (this.#sendQueue.size > 0) {
      const head = this.#sendQueue.shift()
      let offsetFrom = 0

      while (offsetFrom < head.length) {
        const remaining = head.length - offsetFrom
        const chunkSize = remaining > this.#delta ? this.#delta : remaining

        if (this.#peerLastAck !== null) {
          const diff = (this.#sequenceNumber - this.#peerLastAck) >>> 0
          const inflight = diff > 0x80000000 ? 0 : diff
          if (inflight + chunkSize > this.#peerWindow) {
            // Window full — re-queue remainder and pause source.
            this.#sendQueue.unshift(head.slice(offsetFrom))
            if (!this.#paused && this.#socket) {
              this.#paused = true
              this.#socket.pause()
            }
            return
          }
        }

        const offsetTo = offsetFrom + chunkSize
        const subData = head.slice(offsetFrom, offsetTo)

        const ip4Packet = this.#createTCP({
          data: subData,
          ACK: true,
          PSH: offsetTo === head.length && this.#sendQueue.size === 0,
        })

        this.#emitIp4Packet(ip4Packet)

        this.#sequenceNumber += subData.length
        offsetFrom = offsetTo
      }
    }

    if (this.#paused && this.#socket) {
      this.#paused = false
      this.#socket.resume()
    }
  }

  /**
   * Capture peer's ack/window on every incoming TCP message; flush queued
   * outbound data if the window opened up.
   *
   * Cumulative ACKs only advance — duplicates and reordered packets carrying
   * older ack numbers must not regress #peerLastAck, otherwise inflight gets
   * inflated and the send-side flow control deadlocks. Window updates are
   * always honored regardless of whether the ack number advanced.
   */
  #updatePeerAck(incomingTCPMessage) {
    if (incomingTCPMessage.window !== undefined) {
      this.#peerWindow = incomingTCPMessage.window
    }

    const newAck = incomingTCPMessage.acknowledgmentNumber
    if (this.#peerLastAck === null) {
      this.#peerLastAck = newAck
    } else {
      const advance = (newAck - this.#peerLastAck) >>> 0
      if (advance !== 0 && advance < 0x80000000) {
        this.#peerLastAck = newAck
      }
    }

    if (this.#sendQueue.size > 0 || this.#paused) {
      this.#flushSendQueue()
    }
  }

  /**
   * @param {IP4Packet} ip4Packet
   */
  #emitIp4Packet(ip4Packet) {
    // console.log(ip4Packet.debugView())
    // this.#sequenceNumber += ip4Packet.getTCPMessage().data.length
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
    if (this.#tcpStage === 'fin_ack' && tcpMessage.FIN && this.#acknowledgmentNumber === tcpMessage.sequenceNumber) {
      this.#acknowledgmentNumber += 1
      this.#emitIp4Packet(this.#createTCP({ ACK: true }))
      // this.#logger.debug(() => '[TCP_STREAM] grace close connection by server')
      this.#emitClose()
      return
    }

    // client init fin
    if (this.#tcpStage === 'fin_client') {
      this.#acknowledgmentNumber += 1
      // this.#logger.debug(() => '[TCP_STREAM] send ack fin')
      this.#emitIp4Packet(this.#createTCP({ ACK: true }))
      this.#emitIp4Packet(this.#createTCP({ FIN: true, ACK: true }))
      this.#sequenceNumber += 1
      this.#tcpStage = 'fin_client2'
      return
    }

    if (tcpMessage.ACK && this.#tcpStage === 'fin_client2') {
      if (tcpMessage.acknowledgmentNumber === this.#sequenceNumber) {
        this.#logger.debug(() => ({
          f: `${TCP_STREAM}[id-${this.#socketId}]`,
          ip: this.#destinationIP.toString(),
          log: `grace close socket by client`,
        }))

        this.#emitClose()
      }
    }
  }

  /**
   * Feed an incoming TCP data segment through reassembly. Advances #rcvNxt
   * only when bytes arrive in order; buffers future segments by their
   * sequence number; trims duplicates/overlaps.
   *
   * @param {number} seq starting peer-seq of `data`
   * @param {Buffer} data payload bytes
   */
  #feedData(seq, data) {
    if (!data || data.length === 0 || this.#rcvNxt === null) {
      return
    }

    // Trim bytes that fall behind rcvNxt (duplicates, partial overlap).
    const offset = (this.#rcvNxt - seq) >>> 0
    if (offset !== 0 && offset < 0x80000000) {
      if (offset >= data.length) {
        // entirely already-delivered — drop
        return
      }
      data = data.slice(offset)
      seq = this.#rcvNxt
    }

    if (seq === this.#rcvNxt) {
      this.#deliverInOrder(data)
      this.#rcvNxt = (this.#rcvNxt + data.length) >>> 0
      this.#drainPending()
    } else {
      // Future segment — buffer until rcvNxt catches up. Skip if we already
      // have a copy at this seq (defensive against retransmits).
      if (!this.#pendingSegments.has(seq)) {
        this.#pendingSegments.set(seq, data)
      }
    }
  }

  #deliverInOrder(data) {
    if (this.#socketStage === 'established' && this.#socket?.writable) {
      this.#socket.write(data)
    } else {
      this.#writeQueue.push(data)
    }
  }

  #drainPending() {
    while (this.#pendingSegments.has(this.#rcvNxt)) {
      const data = this.#pendingSegments.get(this.#rcvNxt)
      this.#pendingSegments.delete(this.#rcvNxt)
      this.#deliverInOrder(data)
      this.#rcvNxt = (this.#rcvNxt + data.length) >>> 0
    }
  }

  /**
   * Flush any in-order chunks that were queued before the upstream socket
   * was writable (called after #onSocketConnect transitions to 'established').
   */
  #writeDataToSocket() {
    if (!this.#writeQueue.length) {
      return
    }

    if (this.#socketStage !== 'established') {
      return
    }

    if (!this.#socket?.writable) {
      return
    }

    while (this.#writeQueue.length > 0) {
      this.#socket.write(this.#writeQueue.shift())
    }
  }

  async #connect(ipv4Packet) {
    if (this.#socketStage !== 'new') {
      this.#logger.error(() => ({
        f: `${TCP_STREAM}[id-${this.#socketId}]`,
        error: 'socket is not new',
        path: `${this.#sourceIP}:${this.#sourcePort} -> ${this.#destinationIP}:${this.#destinationPort}`,
      }))
      return
    }

    this.#socketStage = 'connecting'
    this.#connectionTimeout = setTimeout(this.close.bind(this), SOCKET_CONNECTION_TIMEOUT)

    this.#logger.info(() => ({
      f: `${TCP_STREAM}[id-${this.#socketId}]`,
      log: 'connecting',
      path: `${this.#sourceIP}:${this.#sourcePort} -> ${this.#destinationIP}:${this.#destinationPort}`,
    }))

    const sourceIP = this.#sourceIP.toString()
    const sourcePort = this.#sourcePort
    const port = this.#destinationPort
    const host = this.#destinationIP.toString()

    this.#socket = await Promise.resolve(
      this.#tcpSocketFactory(
        {
          host,
          port,
          sourcePort,
          sourceIP,
          socketId: this.#socketId,
        },
        this.#onSocketConnect.bind(this, ipv4Packet),
      ),
    ).catch(() => null)

    if (!this.#socket) {
      clearTimeout(this.#connectionTimeout)
      this.#onSocketError(new Error('Connection failed.'))
      return
    }

    this.#socket.on('data', (this.#onSocketDataBind = this.#onSocketData.bind(this)))
    this.#socket.on('error', (this.#onSocketErrorBind = this.#onSocketError.bind(this)))
    this.#socket.on('close', (this.#closeBind = this.close.bind(this)))
  }

  #onSocketConnect(ip4Packet) {
    this.#logger.debug(() => ({ f: `${TCP_STREAM}[id-${this.#socketId}] connected` }))
    clearTimeout(this.#connectionTimeout)
    this.#socketStage = 'established'
    this.#emitIp4Packet(ip4Packet)
    this.#writeDataToSocket()
  }

  #emitClose() {
    if (this.#finTimeout) {
      clearTimeout(this.#finTimeout)
      this.#finTimeout = null
    }
    this.emit('close')
  }

  /**
   * @param {TCPMessage} incomingTCPMessage
   */
  send(incomingTCPMessage) {
    if (incomingTCPMessage.RST) {
      this.#logger.debug(() => ({
        f: `${TCP_STREAM}[id-${this.#socketId}]`,
        ip: this.#destinationIP.toString(),
        log: `connection reset`,
      }))
      // this.#logger.debug(() => '[TCP_STREAM] connection reset')
      this.#tcpStage = 'reset'
      this.close()
      this.#emitClose()
      return
    }

    if (this.#tcpStage.includes('fin')) {
      return this.#finStage(incomingTCPMessage)
    }

    if (incomingTCPMessage.FIN) {
      // this.#logger.debug(() => `[TCP_STREAM] fin client ${this.#socketDebugId}`)
      this.#tcpStage = 'fin_client'
      this.#finStage(incomingTCPMessage)
      if (this.#socket && this.#socket.writable) {
        this.#socket.end()
      }
      return
    }

    if (incomingTCPMessage.SYN) {
      if (this.#tcpStage !== 'new') {
        return
      }

      this.#tcpStage = 'syn'
      this.#sequenceNumber = this.#getRandomSequenceNumber()
      this.#acknowledgmentNumber = incomingTCPMessage.sequenceNumber + 1
      this.#rcvNxt = this.#acknowledgmentNumber
      const ipv4TCPSynAckMessage = this.#createTCP({ SYN: true, ACK: true })

      this.#connect(ipv4TCPSynAckMessage)
      return
    }

    if (incomingTCPMessage.ACK && this.#tcpStage === 'syn') {
      this.#tcpStage = 'established'
      this.#sequenceNumber += 1
      this.#updatePeerAck(incomingTCPMessage)
      return
    } // return

    if (incomingTCPMessage.ACK && incomingTCPMessage.data.length === 0) {
      if (
        ((incomingTCPMessage.acknowledgmentNumber - this.#sequenceNumber) & 0xffffffff) !== 0 &&
        ((incomingTCPMessage.acknowledgmentNumber - this.#sequenceNumber) & 0xffffffff) < 0x80000000
      ) {
        return
      }

      this.#updatePeerAck(incomingTCPMessage)
      this.#writeDataToSocket()
      return
    } // return

    if (incomingTCPMessage.ACK) {
      // Reassemble out-of-order segments before delivery — UDP under
      // WireGuard can reorder, so writing in arrival order corrupts streams.
      this.#feedData(incomingTCPMessage.sequenceNumber, incomingTCPMessage.data)
      // Our outgoing ACK reflects rcvNxt so the peer knows what we have
      // contiguously; #acknowledgmentNumber is kept in sync for #createTCP.
      this.#acknowledgmentNumber = this.#rcvNxt
      this.#emitIp4Packet(this.#createTCP({ ACK: true }))
      this.#updatePeerAck(incomingTCPMessage)
    } else {
      this.#logger.error(() => ({ f: `${TCP_STREAM}[id-${this.#socketId}]`, log: `strange socket` }))
    }

    if (this.#socketStage === 'established') {
      this.#writeDataToSocket()
    }
  }

  close() {
    this.#logger.debug(() => ({
      f: `${TCP_STREAM}[id-${this.#socketId}]`,
      ip: this.#destinationIP.toString(),
      log: `close socket`,
    }))

    clearTimeout(this.#connectionTimeout)

    if (this.#socket) {
      this.#socket.off('data', this.#onSocketDataBind)
      this.#socket.off('error', this.#onSocketErrorBind)
      this.#socket.off('close', this.#closeBind)
      this.#socket.destroy()
      this.#socket = null
    }

    if (this.#tcpStage === 'established') {
      this.#tcpStage = 'fin_init'
      this.#emitIp4Packet(this.#createTCP({ FIN: true, ACK: true }))
    }

    // Force-emit close after a grace period if the FIN handshake never
    // completes (peer gone, packet loss). Without this, the TCPContainer
    // hash entry sticks forever and recycled source ports get blocked.
    if (this.#tcpStage !== 'reset' && !this.#finTimeout) {
      this.#finTimeout = setTimeout(() => {
        this.#finTimeout = null
        if (this.#tcpStage !== 'reset') {
          this.#logger.debug?.(() => ({
            f: `${TCP_STREAM}[id-${this.#socketId}]`,
            log: `FIN handshake timed out (stage=${this.#tcpStage}); forcing close`,
          }))
          this.#tcpStage = 'reset'
          this.#emitClose()
        }
      }, FIN_HANDSHAKE_TIMEOUT)
      this.#finTimeout.unref?.()
    }
  }
}

module.exports = TCPStream
