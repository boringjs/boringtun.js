'use strict'

const crypto = require('crypto')
const { generateX25519KeyPair, getPublicKeyFromPrivate } = require('./crypto/noise-helpers.js')
const { Handshake } = require('./crypto/noise.js')
const Logger = require('./utils/logger.js')

// --- Constants ---
const HANDSHAKE_INIT = 1
const HANDSHAKE_RESP = 2
const COOKIE_REPLY = 3
const DATA = 4

const HANDSHAKE_INIT_SZ = 148
const HANDSHAKE_RESP_SZ = 92
const COOKIE_REPLY_SZ = 64
const DATA_OVERHEAD_SZ = 32
const DATA_OFFSET = 16

const N_SESSIONS = 8
const MAX_QUEUE_DEPTH = 256

// Timer constants (in ms)
const REKEY_AFTER_TIME = 120_000
const REJECT_AFTER_TIME = 180_000
const REKEY_ATTEMPT_TIME = 90_000
const REKEY_TIMEOUT = 5_000
const KEEPALIVE_TIMEOUT = 10_000
const COOKIE_EXPIRATION_TIME = 120_000

// Result type constants
const WIREGUARD_DONE = 0
const WRITE_TO_NETWORK = 1
const WIREGUARD_ERROR = 2
const WRITE_TO_TUNNEL_IPV4 = 4
const WRITE_TO_TUNNEL_IPV6 = 6

// --- WireguardTunnel ---

class WireguardTunnel {
  #privateKeyB64
  #peerPublicKeyB64
  #handshake
  #sessions = new Array(N_SESSIONS).fill(null)
  #current = 0
  #packetQueue = []
  #txBytes = 0
  #rxBytes = 0
  #timeStarted = Date.now()
  #timers = {
    current: 0,
    sessionEstablished: 0,
    lastHandshakeStarted: 0,
    lastPacketReceived: 0,
    lastPacketSent: 0,
    lastDataPacketReceived: 0,
    lastDataPacketSent: 0,
    cookieReceived: 0,
    persistentKeepalive: 0,
  }
  #sessionTimers = new Array(N_SESSIONS).fill(0)
  #isInitiator = false
  #wantKeepalive = false
  #wantHandshake = false
  #persistentKeepalive
  #logger

  constructor({ privateKey, publicKey, preSharedKey = '', keepAlive = 0, index = 0, logger }) {
    this.#privateKeyB64 = privateKey
    this.#peerPublicKeyB64 = publicKey
    this.#logger = logger ?? new Logger()

    const privateKeyBuf = Buffer.from(privateKey, 'base64')
    const publicKeyBuf = getPublicKeyFromPrivate(privateKeyBuf)
    const peerPublicKeyBuf = Buffer.from(publicKey, 'base64')

    let psk = null
    if (preSharedKey && preSharedKey.length > 0) {
      psk = Buffer.from(preSharedKey, 'base64')
    }

    this.#handshake = new Handshake(
      privateKeyBuf,
      publicKeyBuf,
      peerPublicKeyBuf,
      (index & 0xffffff) << 8,
      psk,
      this.#logger,
    )

    this.#persistentKeepalive = keepAlive
  }

  // --- Timer helpers ---

  #now() {
    return Date.now() - this.#timeStarted
  }

  #timerTick(name) {
    if (name === 'lastPacketReceived') {
      this.#wantKeepalive = true
      this.#wantHandshake = false
    } else if (name === 'lastPacketSent') {
      this.#wantHandshake = true
      this.#wantKeepalive = false
    }
    this.#timers[name] = this.#timers.current
  }

  #timerTickSessionEstablished(isInitiator, sessionIdx) {
    this.#timerTick('sessionEstablished')
    this.#sessionTimers[sessionIdx % N_SESSIONS] = this.#timers.current
    this.#isInitiator = isInitiator
  }

  #clearAll() {
    this.#sessions.fill(null)
    this.#packetQueue = []
    const now = this.#now()
    for (const key of Object.keys(this.#timers)) {
      this.#timers[key] = now
    }
    this.#wantKeepalive = false
    this.#wantHandshake = false
  }

  #setCurrentSession(newIdx) {
    const curIdx = this.#current
    if (curIdx === newIdx) return
    if (
      this.#sessions[curIdx % N_SESSIONS] === null ||
      this.#sessionTimers[newIdx % N_SESSIONS] >= this.#sessionTimers[curIdx % N_SESSIONS]
    ) {
      this.#current = newIdx
    }
  }

  // --- Packet parsing ---

  static #parsePacket(src) {
    if (src.length < 4) return null
    const type = src.readUInt32LE(0)
    switch (type) {
      case HANDSHAKE_INIT:
        if (src.length !== HANDSHAKE_INIT_SZ) return null
        return { type: HANDSHAKE_INIT }
      case HANDSHAKE_RESP:
        if (src.length !== HANDSHAKE_RESP_SZ) return null
        return { type: HANDSHAKE_RESP }
      case COOKIE_REPLY:
        if (src.length !== COOKIE_REPLY_SZ) return null
        return { type: COOKIE_REPLY }
      case DATA:
        if (src.length < DATA_OVERHEAD_SZ) return null
        return { type: DATA }
      default:
        return null
    }
  }

  // --- Encapsulation ---

  #encapsulate(src) {
    const current = this.#current
    const session = this.#sessions[current % N_SESSIONS]
    if (session) {
      const packet = session.formatPacketData(src)
      this.#timerTick('lastPacketSent')
      if (src.length > 0) {
        this.#timerTick('lastDataPacketSent')
      }
      this.#txBytes += src.length
      return { type: WRITE_TO_NETWORK, data: packet }
    }

    this.#queuePacket(src)
    return this.#formatHandshakeInitiation(false)
  }

  #formatHandshakeInitiation(forceResend) {
    if (this.#handshake.isInProgress() && !forceResend) {
      this.#logger.debug(() => `[TUNNEL] formatHandshakeInitiation: already in progress, skipping`)
      return { type: WIREGUARD_DONE, data: Buffer.alloc(0) }
    }

    if (this.#handshake.isExpired()) {
      this.#clearTimers()
    }

    const startingNew = !this.#handshake.isInProgress()

    try {
      const packet = this.#handshake.formatHandshakeInitiation()
      if (startingNew) {
        this.#timerTick('lastHandshakeStarted')
      }
      this.#timerTick('lastPacketSent')
      return { type: WRITE_TO_NETWORK, data: packet }
    } catch (e) {
      this.#logger.warn(() => `[TUNNEL] formatHandshakeInitiation: error: ${e.message}`)
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }
  }

  #clearTimers() {
    const now = this.#now()
    for (const key of Object.keys(this.#timers)) {
      this.#timers[key] = now
    }
    this.#wantKeepalive = false
    this.#wantHandshake = false
  }

  // --- Decapsulation ---

  #decapsulate(src) {
    if (src.length === 0) {
      return this.#sendQueuedPacket()
    }

    const parsed = WireguardTunnel.#parsePacket(src)
    if (!parsed) {
      this.#logger.warn(
        () =>
          `[TUNNEL] decapsulate: unparseable packet, length=${src.length} first4=${src.length >= 4 ? src.readUInt32LE(0) : 'N/A'}`,
      )
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }

    this.#logger.debug(() => `[TUNNEL] decapsulate: packet type=${parsed.type} length=${src.length}`)

    switch (parsed.type) {
      case HANDSHAKE_INIT:
        return this.#handleHandshakeInit(src)
      case HANDSHAKE_RESP:
        return this.#handleHandshakeResponse(src)
      case COOKIE_REPLY:
        return this.#handleCookieReply(src)
      case DATA:
        return this.#handleData(src)
      default:
        return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }
  }

  #handleHandshakeInit(src) {
    this.#logger.debug(() => `[TUNNEL] handleHandshakeInit`)
    const result = this.#handshake.receiveHandshakeInitiation(src)
    if (!result) {
      this.#logger.warn(() => `[TUNNEL] handleHandshakeInit: handshake.receiveHandshakeInitiation returned null`)
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }

    const { packet, session } = result
    const index = session.receivingIndex
    this.#sessions[index % N_SESSIONS] = session
    this.#logger.debug(
      () => `[TUNNEL] handleHandshakeInit: session stored at slot ${index % N_SESSIONS}, receivingIndex=${index}`,
    )

    this.#timerTick('lastPacketReceived')
    this.#timerTick('lastPacketSent')
    this.#timerTickSessionEstablished(false, index)

    return { type: WRITE_TO_NETWORK, data: packet }
  }

  #handleHandshakeResponse(src) {
    this.#logger.debug(() => `[TUNNEL] handleHandshakeResponse`)
    const session = this.#handshake.receiveHandshakeResponse(src)
    if (!session) {
      this.#logger.warn(() => `[TUNNEL] handleHandshakeResponse: handshake.receiveHandshakeResponse returned null`)
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }

    const keepalive = session.formatPacketData(Buffer.alloc(0))
    const lIdx = session.receivingIndex
    const index = lIdx % N_SESSIONS
    this.#sessions[index] = session
    this.#logger.debug(
      () =>
        `[TUNNEL] handleHandshakeResponse: session stored at slot ${index}, receivingIndex=${lIdx}, sending keepalive`,
    )

    this.#timerTick('lastPacketReceived')
    this.#timerTickSessionEstablished(true, index)
    this.#setCurrentSession(lIdx)

    return { type: WRITE_TO_NETWORK, data: keepalive }
  }

  #handleCookieReply(src) {
    this.#logger.debug(() => `[TUNNEL] handleCookieReply`)
    this.#handshake.receiveCookieReply(src)
    this.#timerTick('lastPacketReceived')
    this.#timerTick('cookieReceived')
    return { type: WIREGUARD_DONE, data: Buffer.alloc(0) }
  }

  #handleData(src) {
    const receiverIdx = src.readUInt32LE(4)
    const counter = src.readUInt32LE(8) + src.readUInt32LE(12) * 0x100000000
    const encryptedData = src.subarray(DATA_OFFSET)

    this.#logger.debug(
      () => `[TUNNEL] handleData: receiverIdx=${receiverIdx} counter=${counter} encLen=${encryptedData.length}`,
    )

    const idx = receiverIdx % N_SESSIONS
    const session = this.#sessions[idx]
    if (!session) {
      this.#logger.warn(() => `[TUNNEL] handleData: no session at slot ${idx}`)
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }

    const plaintext = session.receivePacketData(receiverIdx, counter, encryptedData)
    if (plaintext === null) {
      this.#logger.debug(() => `[TUNNEL] handleData: session.receivePacketData returned null`)
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }

    this.#setCurrentSession(receiverIdx)
    this.#timerTick('lastPacketReceived')

    return this.#validateDecapsulatedPacket(plaintext)
  }

  #validateDecapsulatedPacket(packet) {
    if (packet.length === 0) {
      this.#logger.debug(() => `[TUNNEL] validateDecapsulatedPacket: keepalive (empty)`)
      return { type: WIREGUARD_DONE, data: Buffer.alloc(0) }
    }

    const version = packet[0] >> 4
    if (version === 4 && packet.length >= 20) {
      const len = packet.readUInt16BE(2)
      if (len > packet.length) {
        this.#logger.warn(
          () => `[TUNNEL] validateDecapsulatedPacket: IPv4 length field ${len} > packet.length ${packet.length}`,
        )
        return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
      }
      this.#timerTick('lastDataPacketReceived')
      this.#rxBytes += len
      return { type: WRITE_TO_TUNNEL_IPV4, data: Buffer.from(packet.subarray(0, len)) }
    }

    if (version === 6 && packet.length >= 40) {
      const payloadLen = packet.readUInt16BE(4)
      const len = payloadLen + 40
      if (len > packet.length) {
        this.#logger.warn(
          () => `[TUNNEL] validateDecapsulatedPacket: IPv6 length field ${len} > packet.length ${packet.length}`,
        )
        return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
      }
      this.#timerTick('lastDataPacketReceived')
      this.#rxBytes += len
      return { type: WRITE_TO_TUNNEL_IPV6, data: Buffer.from(packet.subarray(0, len)) }
    }

    this.#logger.warn(
      () => `[TUNNEL] validateDecapsulatedPacket: invalid IP packet, version=${version} length=${packet.length}`,
    )
    return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
  }

  #queuePacket(packet) {
    if (this.#packetQueue.length < MAX_QUEUE_DEPTH) {
      this.#packetQueue.push(Buffer.from(packet))
    }
  }

  #sendQueuedPacket() {
    if (this.#packetQueue.length > 0) {
      const packet = this.#packetQueue.shift()
      const result = this.#encapsulate(packet)
      if (result.type === WIREGUARD_ERROR) {
        this.#packetQueue.unshift(packet)
        return { type: WIREGUARD_DONE, data: Buffer.alloc(0) }
      }
      return result
    }
    return { type: WIREGUARD_DONE, data: Buffer.alloc(0) }
  }

  // --- Public API ---

  write(src) {
    return this.#encapsulate(src)
  }

  read(src) {
    return this.#decapsulate(src)
  }

  tick() {
    let handshakeRequired = false
    let keepaliveRequired = false

    const now = this.#now()
    this.#timers.current = now

    for (let i = 0; i < N_SESSIONS; i++) {
      if (now - this.#sessionTimers[i] > REJECT_AFTER_TIME && this.#sessions[i]) {
        this.#logger.debug(() => `[TUNNEL] tick: expiring session at slot ${i}`)
        this.#sessions[i] = null
        this.#sessionTimers[i] = now
      }
    }

    if (this.#handshake.isExpired()) {
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }

    if (this.#handshake.hasCookie() && now - this.#timers.cookieReceived >= COOKIE_EXPIRATION_TIME) {
      this.#handshake.clearCookie()
    }

    if (now - this.#timers.sessionEstablished >= REJECT_AFTER_TIME * 3) {
      this.#logger.info(() => `[TUNNEL] tick: connection expired (3x REJECT_AFTER_TIME)`)
      this.#handshake.setExpired()
      this.#clearAll()
      return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
    }

    const handshakeTimer = this.#handshake.timer()
    if (handshakeTimer !== null) {
      if (now - this.#timers.lastHandshakeStarted >= REKEY_ATTEMPT_TIME) {
        this.#logger.warn(() => `[TUNNEL] tick: handshake attempt timeout (REKEY_ATTEMPT_TIME)`)
        this.#handshake.setExpired()
        this.#clearAll()
        return { type: WIREGUARD_ERROR, data: Buffer.alloc(0) }
      }

      if (Date.now() - handshakeTimer >= REKEY_TIMEOUT) {
        this.#logger.debug(() => `[TUNNEL] tick: handshake retry (REKEY_TIMEOUT)`)
        handshakeRequired = true
      }
    } else {
      if (this.#isInitiator) {
        if (
          this.#timers.sessionEstablished < this.#timers.lastDataPacketSent &&
          now - this.#timers.sessionEstablished >= REKEY_AFTER_TIME
        ) {
          this.#logger.debug(() => `[TUNNEL] tick: rekey (REKEY_AFTER_TIME on send)`)
          handshakeRequired = true
        }

        if (
          this.#timers.sessionEstablished < this.#timers.lastDataPacketReceived &&
          now - this.#timers.sessionEstablished >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        ) {
          this.#logger.debug(() => `[TUNNEL] tick: rekey (REJECT_AFTER_TIME - KEEPALIVE - REKEY on recv)`)
          handshakeRequired = true
        }
      }

      if (
        this.#timers.lastDataPacketSent > this.#timers.lastPacketReceived &&
        now - this.#timers.lastPacketReceived >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT &&
        this.#wantHandshake
      ) {
        this.#logger.debug(() => `[TUNNEL] tick: rekey (KEEPALIVE + REKEY_TIMEOUT no response)`)
        this.#wantHandshake = false
        handshakeRequired = true
      }

      if (!handshakeRequired) {
        if (
          this.#timers.lastDataPacketReceived > this.#timers.lastPacketSent &&
          now - this.#timers.lastPacketSent >= KEEPALIVE_TIMEOUT &&
          this.#wantKeepalive
        ) {
          this.#logger.debug(() => `[TUNNEL] tick: sending keepalive (KEEPALIVE_TIMEOUT)`)
          this.#wantKeepalive = false
          keepaliveRequired = true
        }

        if (
          this.#persistentKeepalive > 0 &&
          now - this.#timers.persistentKeepalive >= this.#persistentKeepalive * 1000
        ) {
          this.#logger.debug(() => `[TUNNEL] tick: persistent keepalive`)
          this.#timerTick('persistentKeepalive')
          keepaliveRequired = true
        }
      }
    }

    if (handshakeRequired) {
      return this.#formatHandshakeInitiation(true)
    }

    if (keepaliveRequired) {
      return this.#encapsulate(Buffer.alloc(0))
    }

    return { type: WIREGUARD_DONE, data: Buffer.alloc(0) }
  }

  forceHandshake() {
    return this.#formatHandshakeInitiation(true)
  }

  getStats() {
    return {
      txBytes: this.#txBytes,
      rxBytes: this.#rxBytes,
      lastHandshakeRtt: this.#handshake.lastRtt,
      lastHandshake: this.#timers.sessionEstablished > 0 ? this.#timeStarted + this.#timers.sessionEstablished : 0,
    }
  }

  getPrivateKey() {
    return this.#privateKeyB64
  }

  getPeerPublicKey() {
    return this.#peerPublicKeyB64
  }

  // --- Static helpers ---

  /** @returns {{privateKey: string, publicKey: string}} */
  static generateKeyPair() {
    const { privateKey, publicKey } = generateX25519KeyPair()
    return {
      privateKey: privateKey.toString('base64'),
      publicKey: publicKey.toString('base64'),
    }
  }

  /** @returns {string} */
  static generatePrivateKey() {
    const { privateKey } = generateX25519KeyPair()
    return privateKey.toString('base64')
  }

  /**
   * @param {string|Buffer} privateKey
   * @returns {string}
   */
  static getPublicKeyFrom(privateKey) {
    if (typeof privateKey === 'string') {
      if (!WireguardTunnel.checkValidKey(privateKey)) {
        throw new TypeError('Invalid input string key')
      }
      privateKey = Buffer.from(privateKey, 'base64')
    }

    if (typeof privateKey === 'object' && !!privateKey && privateKey instanceof Buffer) {
      if (privateKey.length !== 32) {
        throw new TypeError('Invalid buffer length')
      }
      return getPublicKeyFromPrivate(privateKey).toString('base64')
    }

    throw new TypeError('Invalid type of privateKey')
  }

  /**
   * @param {Buffer|string} key
   * @returns {boolean}
   */
  static checkValidKey(key) {
    try {
      const str = typeof key === 'string' ? key : key.toString('base64')
      const buf = Buffer.from(str, 'base64')
      if (buf.length !== 32) return false
      const der = Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), buf])
      crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
      return true
    } catch {
      return false
    }
  }
}

// Static constants
WireguardTunnel.WIREGUARD_DONE = WIREGUARD_DONE
WireguardTunnel.WRITE_TO_NETWORK = WRITE_TO_NETWORK
WireguardTunnel.WIREGUARD_ERROR = WIREGUARD_ERROR
WireguardTunnel.WRITE_TO_TUNNEL_IPV4 = WRITE_TO_TUNNEL_IPV4
WireguardTunnel.WRITE_TO_TUNNEL_IPV6 = WRITE_TO_TUNNEL_IPV6

// Backwards-compatible exports (free functions delegate to static methods)
module.exports = {
  generateKeyPair: WireguardTunnel.generateKeyPair,
  generatePrivateKey: WireguardTunnel.generatePrivateKey,
  getPublicKeyFrom: WireguardTunnel.getPublicKeyFrom,
  checkValidKey: WireguardTunnel.checkValidKey,
  WireguardTunnel,
}
