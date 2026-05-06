'use strict'

const crypto = require('crypto')
const {
  b2s_hash,
  b2s_hmac,
  b2s_hmac2,
  b2s_keyed_mac_16,
  aead_chacha20_seal,
  aead_chacha20_open,
  xchacha20_open,
  x25519,
  generateX25519KeyPair,
  makeNonce,
  INITIAL_CHAIN_KEY,
  INITIAL_CHAIN_HASH,
  LABEL_MAC1,
  LABEL_COOKIE,
} = require('./noise-helpers.js')
const { aeadSeal, aeadOpen } = require('./chacha20poly1305.js')

// --- Constants ---
const HANDSHAKE_INIT_SZ = 148
const HANDSHAKE_RESP_SZ = 92
const COOKIE_REPLY_SZ = 64
const AEAD_SIZE = 16
const DATA = 4
const DATA_OFFSET = 16

// TAI64N base: 2^62 + 37 (leap seconds offset)
const TAI64_BASE = BigInt(2) ** BigInt(62) + BigInt(37)

// --- TAI64N Timestamp ---

function tai64nNow() {
  const now = Date.now()
  const secs = BigInt(Math.floor(now / 1000)) + TAI64_BASE
  const nanos = (now % 1000) * 1_000_000
  const buf = Buffer.alloc(12)
  buf.writeBigUInt64BE(secs, 0)
  buf.writeUInt32BE(nanos, 8)
  return buf
}

function tai64nAfter(a, b) {
  for (let i = 0; i < 12; i++) {
    if (a[i] > b[i]) return true
    if (a[i] < b[i]) return false
  }
  return false
}

// --- Replay counter (sliding window) ---
const WORD_SIZE = 32
const N_WORDS = 32
const N_BITS = WORD_SIZE * N_WORDS

class ReceivingKeyCounterValidator {
  #next = 0
  #receiveCnt = 0
  #bitmap = new Uint32Array(N_WORDS)

  #setBit(idx) {
    const bitIdx = idx % N_BITS
    const word = (bitIdx / WORD_SIZE) | 0
    const bit = bitIdx % WORD_SIZE
    this.#bitmap[word] |= 1 << bit
  }

  #clearBit(idx) {
    const bitIdx = idx % N_BITS
    const word = (bitIdx / WORD_SIZE) | 0
    const bit = bitIdx % WORD_SIZE
    this.#bitmap[word] &= ~(1 << bit)
  }

  #clearWord(idx) {
    const bitIdx = idx % N_BITS
    const word = (bitIdx / WORD_SIZE) | 0
    this.#bitmap[word] = 0
  }

  #checkBit(idx) {
    const bitIdx = idx % N_BITS
    const word = (bitIdx / WORD_SIZE) | 0
    const bit = bitIdx % WORD_SIZE
    return ((this.#bitmap[word] >>> bit) & 1) === 1
  }

  willAccept(counter) {
    if (counter >= this.#next) return true
    if (counter + N_BITS < this.#next) return false
    return !this.#checkBit(counter)
  }

  markDidReceive(counter) {
    if (counter + N_BITS < this.#next) return false

    if (counter === this.#next) {
      this.#setBit(counter)
      this.#next++
      this.#receiveCnt++
      return true
    }

    if (counter < this.#next) {
      if (this.#checkBit(counter)) return false
      this.#setBit(counter)
      this.#receiveCnt++
      return true
    }

    if (counter - this.#next >= N_BITS) {
      this.#bitmap.fill(0)
    } else {
      let i = this.#next
      while (i % WORD_SIZE !== 0 && i < counter) {
        this.#clearBit(i)
        i++
      }
      while (i + WORD_SIZE < counter) {
        this.#clearWord(i)
        i = (i + WORD_SIZE) & ~(WORD_SIZE - 1)
      }
      while (i < counter) {
        this.#clearBit(i)
        i++
      }
    }
    this.#setBit(counter)
    this.#next = counter + 1
    this.#receiveCnt++
    return true
  }
}

// --- Session ---

class Session {
  #sendingIndex
  #sendingKey
  #receivingKey
  #sendingCounter = 0
  #receivingCounter = new ReceivingKeyCounterValidator()
  #logger
  receivingIndex

  constructor(localIndex, peerIndex, receivingKey, sendingKey, logger) {
    this.receivingIndex = localIndex
    this.#sendingIndex = peerIndex
    this.#receivingKey = receivingKey
    this.#sendingKey = sendingKey
    this.#logger = logger
  }

  formatPacketData(src) {
    const counter = this.#sendingCounter++
    const packetLen = DATA_OFFSET + src.length + AEAD_SIZE
    const dst = Buffer.alloc(packetLen)

    dst.writeUInt32LE(DATA, 0)
    dst.writeUInt32LE(this.#sendingIndex, 4)
    dst.writeUInt32LE(counter & 0xffffffff, 8)
    dst.writeUInt32LE(Math.floor(counter / 0x100000000), 12)

    const nonce = makeNonce(counter)
    const sealed = aeadSeal(this.#sendingKey, nonce, src, Buffer.alloc(0))
    sealed.copy(dst, DATA_OFFSET)

    return dst
  }

  receivePacketData(receiverIdx, counter, encryptedData) {
    if (receiverIdx !== this.receivingIndex) {
      this.#logger.debug(
        () => `[SESSION] receivePacketData: wrong index got=${receiverIdx} expected=${this.receivingIndex}`,
      )
      return null
    }
    if (!this.#receivingCounter.willAccept(counter)) {
      this.#logger.debug(() => `[SESSION] receivePacketData: counter ${counter} rejected by replay window`)
      return null
    }

    const nonce = makeNonce(counter)
    try {
      const plaintext = aeadOpen(this.#receivingKey, nonce, encryptedData, Buffer.alloc(0))

      if (!this.#receivingCounter.markDidReceive(counter)) {
        this.#logger.debug(() => `[SESSION] receivePacketData: counter ${counter} rejected on mark`)
        return null
      }

      return plaintext
    } catch (e) {
      this.#logger.warn(() => `[SESSION] receivePacketData: AEAD decryption failed: ${e.message}`)
      return null
    }
  }
}

// --- Handshake ---

class Handshake {
  #staticPrivate
  #staticPublic
  #peerStaticPublic
  #staticShared
  #sendingMac1Key
  #presharedKey
  #nextIndex
  #state = { type: 'none' }
  #previous = { type: 'none' }
  #lastHandshakeTimestamp = Buffer.alloc(12)
  #lastMac1 = null
  #cookieIndex = 0
  #writeCookie = null
  #expired = false
  #logger
  lastRtt = null

  constructor(staticPrivate, staticPublic, peerStaticPublic, globalIdx, presharedKey, logger) {
    this.#staticPrivate = staticPrivate
    this.#staticPublic = staticPublic
    this.#peerStaticPublic = peerStaticPublic
    this.#staticShared = x25519(staticPrivate, peerStaticPublic)
    this.#sendingMac1Key = b2s_hash(LABEL_MAC1, peerStaticPublic)
    this.#presharedKey = presharedKey
    this.#nextIndex = globalIdx
    this.#logger = logger
  }

  isInProgress() {
    return this.#state.type === 'init_sent'
  }

  isExpired() {
    return this.#expired
  }

  setExpired() {
    this.#logger.debug(() => '[HANDSHAKE] setExpired')
    this.#expired = true
    this.#state = { type: 'expired' }
    this.#previous = { type: 'expired' }
  }

  hasCookie() {
    return this.#writeCookie !== null
  }

  clearCookie() {
    this.#writeCookie = null
  }

  timer() {
    if (this.#state.type === 'init_sent') return this.#state.timeSent
    return null
  }

  #incIndex() {
    const index = this.#nextIndex
    const idx8 = index & 0xff
    this.#nextIndex = (index & ~0xff) | ((idx8 + 1) & 0xff)
    return this.#nextIndex
  }

  #appendMac1AndMac2(localIndex, dst) {
    const mac1Off = dst.length - 32
    const mac2Off = dst.length - 16

    const mac1 = b2s_keyed_mac_16(this.#sendingMac1Key, dst.subarray(0, mac1Off))
    mac1.copy(dst, mac1Off)

    let mac2
    if (this.#writeCookie) {
      mac2 = b2s_keyed_mac_16(this.#writeCookie, dst.subarray(0, mac2Off))
    } else {
      mac2 = Buffer.alloc(16)
    }
    mac2.copy(dst, mac2Off)

    this.#cookieIndex = localIndex
    this.#lastMac1 = mac1
    return dst
  }

  formatHandshakeInitiation() {
    const dst = Buffer.alloc(HANDSHAKE_INIT_SZ)
    const localIndex = this.#incIndex()

    this.#logger.debug(() => `[HANDSHAKE] formatHandshakeInitiation: localIndex=${localIndex}`)

    let chainingKey = Buffer.from(INITIAL_CHAIN_KEY)
    let hash = Buffer.from(INITIAL_CHAIN_HASH)

    hash = b2s_hash(hash, this.#peerStaticPublic)

    const { privateKey: ephemeralPrivate, publicKey: ephemeralPublic } = generateX25519KeyPair()

    dst.writeUInt32LE(1, 0) // HANDSHAKE_INIT
    dst.writeUInt32LE(localIndex, 4)
    ephemeralPublic.copy(dst, 8)

    hash = b2s_hash(hash, ephemeralPublic)
    chainingKey = b2s_hmac(b2s_hmac(chainingKey, ephemeralPublic), Buffer.from([0x01]))

    const ephemeralShared = x25519(ephemeralPrivate, this.#peerStaticPublic)
    const temp = b2s_hmac(chainingKey, ephemeralShared)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))
    const key = b2s_hmac2(temp, chainingKey, Buffer.from([0x02]))

    const encryptedStatic = aead_chacha20_seal(key, 0, this.#staticPublic, hash)
    encryptedStatic.copy(dst, 40)

    hash = b2s_hash(hash, encryptedStatic)

    const temp2 = b2s_hmac(chainingKey, this.#staticShared)
    chainingKey = b2s_hmac(temp2, Buffer.from([0x01]))
    const key2 = b2s_hmac2(temp2, chainingKey, Buffer.from([0x02]))

    const timestamp = tai64nNow()
    const encryptedTimestamp = aead_chacha20_seal(key2, 0, timestamp, hash)
    encryptedTimestamp.copy(dst, 88)

    hash = b2s_hash(hash, encryptedTimestamp)

    const timeNow = Date.now()
    this.#previous = this.#state
    this.#state = {
      type: 'init_sent',
      localIndex,
      hash,
      chainingKey,
      ephemeralPrivate,
      timeSent: timeNow,
    }

    this.#logger.debug(() => `[HANDSHAKE] formatHandshakeInitiation: done, state=init_sent`)
    return this.#appendMac1AndMac2(localIndex, dst)
  }

  receiveHandshakeInitiation(src) {
    this.#logger.debug(() => `[HANDSHAKE] receiveHandshakeInitiation: src.length=${src.length}`)

    if (src.length !== HANDSHAKE_INIT_SZ) {
      this.#logger.warn(
        () => `[HANDSHAKE] receiveHandshakeInitiation: bad length ${src.length}, expected ${HANDSHAKE_INIT_SZ}`,
      )
      return null
    }

    const packetType = src.readUInt32LE(0)
    if (packetType !== 1) {
      this.#logger.warn(() => `[HANDSHAKE] receiveHandshakeInitiation: bad packet type ${packetType}`)
      return null
    }

    const peerIndex = src.readUInt32LE(4)
    const peerEphemeralPublic = Buffer.from(src.subarray(8, 40))
    const encryptedStatic = src.subarray(40, 88)
    const encryptedTimestamp = src.subarray(88, 116)

    this.#logger.debug(
      () =>
        `[HANDSHAKE] receiveHandshakeInitiation: peerIndex=${peerIndex} ephPub=${peerEphemeralPublic.subarray(0, 4).toString('hex')}...`,
    )

    let chainingKey = Buffer.from(INITIAL_CHAIN_KEY)
    let hash = Buffer.from(INITIAL_CHAIN_HASH)

    hash = b2s_hash(hash, this.#staticPublic)
    hash = b2s_hash(hash, peerEphemeralPublic)
    chainingKey = b2s_hmac(b2s_hmac(chainingKey, peerEphemeralPublic), Buffer.from([0x01]))

    const ephemeralShared = x25519(this.#staticPrivate, peerEphemeralPublic)
    const temp = b2s_hmac(chainingKey, ephemeralShared)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))
    const key = b2s_hmac2(temp, chainingKey, Buffer.from([0x02]))

    let peerStaticDecrypted
    try {
      peerStaticDecrypted = aead_chacha20_open(key, 0, encryptedStatic, hash)
    } catch (e) {
      this.#logger.warn(() => `[HANDSHAKE] receiveHandshakeInitiation: AEAD open encrypted_static failed: ${e.message}`)
      return null
    }

    if (!crypto.timingSafeEqual(this.#peerStaticPublic, peerStaticDecrypted)) {
      this.#logger.warn(() => `[HANDSHAKE] receiveHandshakeInitiation: peer static key mismatch`)
      this.#logger.warn(() => `[HANDSHAKE]   expected: ${this.#peerStaticPublic.toString('hex')}`)
      this.#logger.warn(() => `[HANDSHAKE]   got:      ${peerStaticDecrypted.toString('hex')}`)
      return null
    }

    this.#logger.debug(() => `[HANDSHAKE] receiveHandshakeInitiation: peer static key verified`)

    hash = b2s_hash(hash, encryptedStatic)

    const temp2 = b2s_hmac(chainingKey, this.#staticShared)
    chainingKey = b2s_hmac(temp2, Buffer.from([0x01]))
    const key2 = b2s_hmac2(temp2, chainingKey, Buffer.from([0x02]))

    let timestamp
    try {
      timestamp = aead_chacha20_open(key2, 0, encryptedTimestamp, hash)
    } catch (e) {
      this.#logger.warn(
        () => `[HANDSHAKE] receiveHandshakeInitiation: AEAD open encrypted_timestamp failed: ${e.message}`,
      )
      return null
    }

    this.#logger.debug(() => `[HANDSHAKE] receiveHandshakeInitiation: timestamp=${timestamp.toString('hex')}`)

    if (!tai64nAfter(timestamp, this.#lastHandshakeTimestamp)) {
      this.#logger.warn(
        () =>
          `[HANDSHAKE] receiveHandshakeInitiation: timestamp not after last (replay?) last=${this.#lastHandshakeTimestamp.toString('hex')}`,
      )
      return null
    }
    this.#lastHandshakeTimestamp = timestamp

    hash = b2s_hash(hash, encryptedTimestamp)

    const mac1Off = HANDSHAKE_INIT_SZ - 32
    const receivingMac1Key = b2s_hash(LABEL_MAC1, this.#staticPublic)
    const expectedMac1 = b2s_keyed_mac_16(receivingMac1Key, src.subarray(0, mac1Off))
    if (!crypto.timingSafeEqual(expectedMac1, src.subarray(mac1Off, mac1Off + 16))) {
      this.#logger.warn(() => `[HANDSHAKE] receiveHandshakeInitiation: mac1 mismatch`)
      this.#logger.warn(() => `[HANDSHAKE]   expected: ${expectedMac1.toString('hex')}`)
      this.#logger.warn(() => `[HANDSHAKE]   got:      ${src.subarray(mac1Off, mac1Off + 16).toString('hex')}`)
      return null
    }

    this.#logger.debug(() => `[HANDSHAKE] receiveHandshakeInitiation: mac1 verified, forming response`)

    this.#previous = this.#state
    this.#state = {
      type: 'init_received',
      chainingKey,
      hash,
      peerEphemeralPublic,
      peerIndex,
    }

    return this.#formatHandshakeResponse()
  }

  #formatHandshakeResponse() {
    if (this.#state.type !== 'init_received') {
      this.#logger.warn(() => `[HANDSHAKE] formatHandshakeResponse: wrong state ${this.#state.type}`)
      return null
    }

    const { chainingKey: ck, hash: h, peerEphemeralPublic, peerIndex } = this.#state
    let chainingKey = ck
    let hash = h

    this.#state = { type: 'none' }

    const dst = Buffer.alloc(HANDSHAKE_RESP_SZ)
    const { privateKey: ephemeralPrivate, publicKey: ephemeralPublic } = generateX25519KeyPair()
    const localIndex = this.#incIndex()

    this.#logger.debug(() => `[HANDSHAKE] formatHandshakeResponse: localIndex=${localIndex} peerIndex=${peerIndex}`)

    dst.writeUInt32LE(2, 0) // HANDSHAKE_RESP
    dst.writeUInt32LE(localIndex, 4)
    dst.writeUInt32LE(peerIndex, 8)
    ephemeralPublic.copy(dst, 12)

    hash = b2s_hash(hash, ephemeralPublic)
    let temp = b2s_hmac(chainingKey, ephemeralPublic)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))

    const eeShared = x25519(ephemeralPrivate, peerEphemeralPublic)
    temp = b2s_hmac(chainingKey, eeShared)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))

    const esShared = x25519(ephemeralPrivate, this.#peerStaticPublic)
    temp = b2s_hmac(chainingKey, esShared)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))

    const psk = this.#presharedKey || Buffer.alloc(32)
    temp = b2s_hmac(chainingKey, psk)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))
    const temp2 = b2s_hmac2(temp, chainingKey, Buffer.from([0x02]))
    const key = b2s_hmac2(temp, temp2, Buffer.from([0x03]))
    hash = b2s_hash(hash, temp2)

    const encryptedNothing = aead_chacha20_seal(key, 0, Buffer.alloc(0), hash)
    encryptedNothing.copy(dst, 44)

    const temp1 = b2s_hmac(chainingKey, Buffer.alloc(0))
    const sessionKey2 = b2s_hmac(temp1, Buffer.from([0x01]))
    const sessionKey3 = b2s_hmac2(temp1, sessionKey2, Buffer.from([0x02]))

    this.#appendMac1AndMac2(localIndex, dst)

    const session = new Session(localIndex, peerIndex, sessionKey2, sessionKey3, this.#logger)
    this.#logger.debug(
      () => `[HANDSHAKE] formatHandshakeResponse: done, session localIdx=${localIndex} peerIdx=${peerIndex}`,
    )
    return { packet: dst, session }
  }

  receiveHandshakeResponse(src) {
    this.#logger.debug(() => `[HANDSHAKE] receiveHandshakeResponse: src.length=${src.length}`)

    if (src.length !== HANDSHAKE_RESP_SZ) {
      this.#logger.warn(
        () => `[HANDSHAKE] receiveHandshakeResponse: bad length ${src.length}, expected ${HANDSHAKE_RESP_SZ}`,
      )
      return null
    }

    const packetType = src.readUInt32LE(0)
    if (packetType !== 2) {
      this.#logger.warn(() => `[HANDSHAKE] receiveHandshakeResponse: bad packet type ${packetType}`)
      return null
    }

    const peerIndex = src.readUInt32LE(4)
    const receiverIdx = src.readUInt32LE(8)
    const peerEphemeralPublic = Buffer.from(src.subarray(12, 44))
    const encryptedNothing = src.subarray(44, 60)

    this.#logger.debug(() => `[HANDSHAKE] receiveHandshakeResponse: peerIndex=${peerIndex} receiverIdx=${receiverIdx}`)
    this.#logger.debug(() => `[HANDSHAKE]   state.type=${this.#state.type} previous.type=${this.#previous.type}`)

    let state, isPrevious
    if (this.#state.type === 'init_sent' && this.#state.localIndex === receiverIdx) {
      state = this.#state
      isPrevious = false
      this.#logger.debug(() => `[HANDSHAKE]   matched current state, localIndex=${state.localIndex}`)
    } else if (this.#previous.type === 'init_sent' && this.#previous.localIndex === receiverIdx) {
      state = this.#previous
      isPrevious = true
      this.#logger.debug(() => `[HANDSHAKE]   matched previous state, localIndex=${state.localIndex}`)
    } else {
      this.#logger.warn(
        () => `[HANDSHAKE] receiveHandshakeResponse: no matching init_sent state for receiverIdx=${receiverIdx}`,
      )
      if (this.#state.type === 'init_sent')
        this.#logger.warn(() => `[HANDSHAKE]   state.localIndex=${this.#state.localIndex}`)
      if (this.#previous.type === 'init_sent')
        this.#logger.warn(() => `[HANDSHAKE]   previous.localIndex=${this.#previous.localIndex}`)
      return null
    }

    const localIndex = state.localIndex
    let hash = b2s_hash(state.hash, peerEphemeralPublic)
    let temp = b2s_hmac(state.chainingKey, peerEphemeralPublic)
    let chainingKey = b2s_hmac(temp, Buffer.from([0x01]))

    const eeShared = x25519(state.ephemeralPrivate, peerEphemeralPublic)
    temp = b2s_hmac(chainingKey, eeShared)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))

    const seShared = x25519(this.#staticPrivate, peerEphemeralPublic)
    temp = b2s_hmac(chainingKey, seShared)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))

    const psk = this.#presharedKey || Buffer.alloc(32)
    temp = b2s_hmac(chainingKey, psk)
    chainingKey = b2s_hmac(temp, Buffer.from([0x01]))
    const temp2 = b2s_hmac2(temp, chainingKey, Buffer.from([0x02]))
    const key = b2s_hmac2(temp, temp2, Buffer.from([0x03]))
    hash = b2s_hash(hash, temp2)

    try {
      aead_chacha20_open(key, 0, encryptedNothing, hash)
    } catch (e) {
      this.#logger.warn(() => `[HANDSHAKE] receiveHandshakeResponse: AEAD open encrypted_nothing failed: ${e.message}`)
      return null
    }

    const temp1 = b2s_hmac(chainingKey, Buffer.alloc(0))
    const sessionKey2 = b2s_hmac(temp1, Buffer.from([0x01]))
    const sessionKey3 = b2s_hmac2(temp1, sessionKey2, Buffer.from([0x02]))

    this.lastRtt = Date.now() - state.timeSent
    this.#logger.debug(() => `[HANDSHAKE] receiveHandshakeResponse: success, rtt=${this.lastRtt}ms`)

    if (isPrevious) {
      this.#previous = { type: 'none' }
    } else {
      this.#state = { type: 'none' }
    }

    return new Session(localIndex, peerIndex, sessionKey3, sessionKey2, this.#logger)
  }

  receiveCookieReply(src) {
    this.#logger.debug(() => `[HANDSHAKE] receiveCookieReply: src.length=${src.length}`)
    if (src.length !== COOKIE_REPLY_SZ) return false
    if (!this.#lastMac1) {
      this.#logger.warn(() => `[HANDSHAKE] receiveCookieReply: no lastMac1`)
      return false
    }

    const receiverIdx = src.readUInt32LE(4)
    if (receiverIdx !== this.#cookieIndex) {
      this.#logger.warn(
        () => `[HANDSHAKE] receiveCookieReply: wrong index got=${receiverIdx} expected=${this.#cookieIndex}`,
      )
      return false
    }

    const nonce = src.subarray(8, 32)
    const encryptedCookie = src.subarray(32, 64)

    const key = b2s_hash(LABEL_COOKIE, this.#peerStaticPublic)

    try {
      const cookie = xchacha20_open(key, nonce, encryptedCookie, this.#lastMac1)
      if (cookie.length !== 16) {
        this.#logger.warn(() => `[HANDSHAKE] receiveCookieReply: bad cookie length ${cookie.length}`)
        return false
      }
      this.#writeCookie = cookie
      this.#logger.debug(() => `[HANDSHAKE] receiveCookieReply: cookie set`)
      return true
    } catch (e) {
      this.#logger.warn(() => `[HANDSHAKE] receiveCookieReply: decryption failed: ${e.message}`)
      return false
    }
  }
}

module.exports = { Handshake, Session }
