'use strict'

// Pure JS ChaCha20-Poly1305 AEAD (RFC 7539)

// --- ChaCha20 ---

function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) | 0
  s[d] ^= s[a]
  s[d] = (s[d] << 16) | (s[d] >>> 16)
  s[c] = (s[c] + s[d]) | 0
  s[b] ^= s[c]
  s[b] = (s[b] << 12) | (s[b] >>> 20)
  s[a] = (s[a] + s[b]) | 0
  s[d] ^= s[a]
  s[d] = (s[d] << 8) | (s[d] >>> 24)
  s[c] = (s[c] + s[d]) | 0
  s[b] ^= s[c]
  s[b] = (s[b] << 7) | (s[b] >>> 25)
}

function chacha20Block(key, counter, nonce) {
  const s = new Array(16)
  s[0] = 0x61707865
  s[1] = 0x3320646e
  s[2] = 0x79622d32
  s[3] = 0x6b206574
  for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(i * 4)
  s[12] = counter
  for (let i = 0; i < 3; i++) s[13 + i] = nonce.readUInt32LE(i * 4)

  const w = s.slice()

  for (let i = 0; i < 10; i++) {
    quarterRound(w, 0, 4, 8, 12)
    quarterRound(w, 1, 5, 9, 13)
    quarterRound(w, 2, 6, 10, 14)
    quarterRound(w, 3, 7, 11, 15)
    quarterRound(w, 0, 5, 10, 15)
    quarterRound(w, 1, 6, 11, 12)
    quarterRound(w, 2, 7, 8, 13)
    quarterRound(w, 3, 4, 9, 14)
  }

  const out = Buffer.alloc(64)
  for (let i = 0; i < 16; i++) {
    out.writeUInt32LE(((w[i] + s[i]) | 0) >>> 0, i * 4)
  }
  return out
}

function chacha20Encrypt(key, counter, nonce, data) {
  const out = Buffer.alloc(data.length)
  let offset = 0
  let ctr = counter
  while (offset < data.length) {
    const block = chacha20Block(key, ctr, nonce)
    const n = Math.min(64, data.length - offset)
    for (let i = 0; i < n; i++) {
      out[offset + i] = data[offset + i] ^ block[i]
    }
    offset += n
    ctr++
  }
  return out
}

// --- Poly1305 ---
// Uses 26-bit limbs (5 limbs = 130 bits) for mod 2^130-5 arithmetic
// Based on poly1305-donna approach

class Poly1305 {
  #h0 = 0
  #h1 = 0
  #h2 = 0
  #h3 = 0
  #h4 = 0
  #r0
  #r1
  #r2
  #r3
  #r4
  #s1
  #s2
  #s3
  #s4
  #pad0
  #pad1
  #pad2
  #pad3
  #buffer = Buffer.alloc(16)
  #leftover = 0

  constructor(key) {
    // Clamp r at 32-bit level first, then convert to 26-bit limbs
    const t0 = key.readUInt32LE(0) & 0x0fffffff
    const t1 = key.readUInt32LE(4) & 0x0ffffffc
    const t2 = key.readUInt32LE(8) & 0x0ffffffc
    const t3 = key.readUInt32LE(12) & 0x0ffffffc

    this.#r0 = t0 & 0x3ffffff
    this.#r1 = ((t0 >>> 26) | (t1 << 6)) & 0x3ffffff
    this.#r2 = ((t1 >>> 20) | (t2 << 12)) & 0x3ffffff
    this.#r3 = ((t2 >>> 14) | (t3 << 18)) & 0x3ffffff
    this.#r4 = (t3 >>> 8) & 0x3ffffff

    this.#s1 = this.#r1 * 5
    this.#s2 = this.#r2 * 5
    this.#s3 = this.#r3 * 5
    this.#s4 = this.#r4 * 5

    this.#pad0 = key.readUInt32LE(16)
    this.#pad1 = key.readUInt32LE(20)
    this.#pad2 = key.readUInt32LE(24)
    this.#pad3 = key.readUInt32LE(28)
  }

  #blocks(data, offset, length, hibit) {
    let h0 = BigInt(this.#h0)
    let h1 = BigInt(this.#h1)
    let h2 = BigInt(this.#h2)
    let h3 = BigInt(this.#h3)
    let h4 = BigInt(this.#h4)
    const r0 = BigInt(this.#r0)
    const r1 = BigInt(this.#r1)
    const r2 = BigInt(this.#r2)
    const r3 = BigInt(this.#r3)
    const r4 = BigInt(this.#r4)
    const s1 = r1 * 5n
    const s2 = r2 * 5n
    const s3 = r3 * 5n
    const s4 = r4 * 5n
    const mask26 = 0x3ffffffn
    const hb = BigInt(hibit)

    while (length >= 16) {
      const t0 = (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0
      const t1 =
        (data[offset + 4] | (data[offset + 5] << 8) | (data[offset + 6] << 16) | (data[offset + 7] << 24)) >>> 0
      const t2 =
        (data[offset + 8] | (data[offset + 9] << 8) | (data[offset + 10] << 16) | (data[offset + 11] << 24)) >>> 0
      const t3 =
        (data[offset + 12] | (data[offset + 13] << 8) | (data[offset + 14] << 16) | (data[offset + 15] << 24)) >>> 0

      h0 += BigInt(t0 & 0x3ffffff)
      h1 += BigInt(((t0 >>> 26) | (t1 << 6)) & 0x3ffffff)
      h2 += BigInt(((t1 >>> 20) | (t2 << 12)) & 0x3ffffff)
      h3 += BigInt(((t2 >>> 14) | (t3 << 18)) & 0x3ffffff)
      h4 += BigInt(t3 >>> 8) | hb

      const d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
      const d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
      const d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
      const d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
      const d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

      let c
      c = d0 >> 26n
      h0 = d0 & mask26
      const e1 = d1 + c
      c = e1 >> 26n
      h1 = e1 & mask26
      const e2 = d2 + c
      c = e2 >> 26n
      h2 = e2 & mask26
      const e3 = d3 + c
      c = e3 >> 26n
      h3 = e3 & mask26
      const e4 = d4 + c
      c = e4 >> 26n
      h4 = e4 & mask26
      h0 += c * 5n
      c = h0 >> 26n
      h0 &= mask26
      h1 += c

      offset += 16
      length -= 16
    }

    this.#h0 = Number(h0)
    this.#h1 = Number(h1)
    this.#h2 = Number(h2)
    this.#h3 = Number(h3)
    this.#h4 = Number(h4)
  }

  update(data) {
    let offset = 0
    let length = data.length

    if (this.#leftover > 0) {
      const want = Math.min(16 - this.#leftover, length)
      data.copy(this.#buffer, this.#leftover, offset, offset + want)
      this.#leftover += want
      offset += want
      length -= want
      if (this.#leftover < 16) return
      this.#blocks(this.#buffer, 0, 16, 1 << 24)
      this.#leftover = 0
    }

    if (length >= 16) {
      const full = length & ~15
      this.#blocks(data, offset, full, 1 << 24)
      offset += full
      length -= full
    }

    if (length > 0) {
      data.copy(this.#buffer, 0, offset, offset + length)
      this.#leftover = length
    }
  }

  finish() {
    if (this.#leftover > 0) {
      this.#buffer[this.#leftover] = 1
      this.#buffer.fill(0, this.#leftover + 1, 16)
      this.#blocks(this.#buffer, 0, 16, 0)
    }

    // Final carry propagation
    let h0 = this.#h0
    let h1 = this.#h1
    let h2 = this.#h2
    let h3 = this.#h3
    let h4 = this.#h4

    let c = h1 >>> 26
    h1 &= 0x3ffffff
    h2 += c
    c = h2 >>> 26
    h2 &= 0x3ffffff
    h3 += c
    c = h3 >>> 26
    h3 &= 0x3ffffff
    h4 += c
    c = h4 >>> 26
    h4 &= 0x3ffffff
    h0 += c * 5
    c = h0 >>> 26
    h0 &= 0x3ffffff
    h1 += c

    // Compute h + 5 to check if >= 2^130-5
    let g0 = h0 + 5
    c = g0 >>> 26
    g0 &= 0x3ffffff
    let g1 = h1 + c
    c = g1 >>> 26
    g1 &= 0x3ffffff
    let g2 = h2 + c
    c = g2 >>> 26
    g2 &= 0x3ffffff
    let g3 = h3 + c
    c = g3 >>> 26
    g3 &= 0x3ffffff
    let g4 = h4 + c - (1 << 26)

    // If g4 bit 31 is set → h < p → use h; otherwise use g
    const mask = (g4 >>> 31) - 1
    const nmask = ~mask
    h0 = (h0 & nmask) | (g0 & mask)
    h1 = (h1 & nmask) | (g1 & mask)
    h2 = (h2 & nmask) | (g2 & mask)
    h3 = (h3 & nmask) | (g3 & mask)
    h4 = (h4 & nmask) | (g4 & mask)

    // Convert 26-bit limbs to 4 x 32-bit words
    let f0 = (h0 | (h1 << 26)) >>> 0
    let f1 = ((h1 >>> 6) | (h2 << 20)) >>> 0
    let f2 = ((h2 >>> 12) | (h3 << 14)) >>> 0
    let f3 = ((h3 >>> 18) | (h4 << 8)) >>> 0

    // Add pad (s)
    let carry = 0
    let v
    v = f0 + this.#pad0 + carry
    f0 = v >>> 0
    carry = v - f0 !== 0 ? 1 : v >= 0x100000000 ? 1 : 0
    // safer carry: if v >= 2^32
    carry = v > 0xffffffff ? 1 : 0

    v = f1 + this.#pad1 + carry
    carry = v > 0xffffffff ? 1 : 0
    f1 = v >>> 0

    v = f2 + this.#pad2 + carry
    carry = v > 0xffffffff ? 1 : 0
    f2 = v >>> 0

    v = f3 + this.#pad3 + carry
    f3 = v >>> 0

    const out = Buffer.alloc(16)
    out.writeUInt32LE(f0, 0)
    out.writeUInt32LE(f1, 4)
    out.writeUInt32LE(f2, 8)
    out.writeUInt32LE(f3, 12)
    return out
  }
}

// --- AEAD Construction (RFC 7539 Section 2.8) ---

function pad16(len) {
  const rem = len % 16
  return rem === 0 ? 0 : 16 - rem
}

function aeadSeal(key, nonce, plaintext, aad) {
  // 1. Generate Poly1305 one-time key
  const otk = chacha20Block(key, 0, nonce).subarray(0, 32)

  // 2. Encrypt plaintext with counter starting at 1
  const ciphertext = chacha20Encrypt(key, 1, nonce, plaintext)

  // 3. Construct Poly1305 input and compute tag
  const mac = new Poly1305(otk)
  mac.update(aad)
  if (aad.length % 16 !== 0) mac.update(Buffer.alloc(pad16(aad.length)))
  mac.update(ciphertext)
  if (ciphertext.length % 16 !== 0) mac.update(Buffer.alloc(pad16(ciphertext.length)))

  const lengths = Buffer.alloc(16)
  lengths.writeUInt32LE(aad.length, 0)
  lengths.writeUInt32LE(0, 4)
  lengths.writeUInt32LE(ciphertext.length, 8)
  lengths.writeUInt32LE(0, 12)
  mac.update(lengths)

  const tag = mac.finish()

  return Buffer.concat([ciphertext, tag])
}

function aeadOpen(key, nonce, data, aad) {
  if (data.length < 16) throw new Error('InvalidAeadTag')

  const ciphertext = data.subarray(0, data.length - 16)
  const receivedTag = data.subarray(data.length - 16)

  // 1. Generate Poly1305 one-time key
  const otk = chacha20Block(key, 0, nonce).subarray(0, 32)

  // 2. Compute expected tag
  const mac = new Poly1305(otk)
  mac.update(aad)
  if (aad.length % 16 !== 0) mac.update(Buffer.alloc(pad16(aad.length)))
  mac.update(ciphertext)
  if (ciphertext.length % 16 !== 0) mac.update(Buffer.alloc(pad16(ciphertext.length)))

  const lengths = Buffer.alloc(16)
  lengths.writeUInt32LE(aad.length, 0)
  lengths.writeUInt32LE(0, 4)
  lengths.writeUInt32LE(ciphertext.length, 8)
  lengths.writeUInt32LE(0, 12)
  mac.update(lengths)

  const expectedTag = mac.finish()

  // 3. Constant-time tag comparison
  let diff = 0
  for (let i = 0; i < 16; i++) diff |= receivedTag[i] ^ expectedTag[i]
  if (diff !== 0) throw new Error('InvalidAeadTag')

  // 4. Decrypt
  return chacha20Encrypt(key, 1, nonce, ciphertext)
}

// --- HChaCha20 (for XChaCha20-Poly1305) ---

function hchacha20(key, nonce16) {
  const s = new Array(16)
  s[0] = 0x61707865
  s[1] = 0x3320646e
  s[2] = 0x79622d32
  s[3] = 0x6b206574
  for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(i * 4)
  for (let i = 0; i < 4; i++) s[12 + i] = nonce16.readUInt32LE(i * 4)

  for (let i = 0; i < 10; i++) {
    quarterRound(s, 0, 4, 8, 12)
    quarterRound(s, 1, 5, 9, 13)
    quarterRound(s, 2, 6, 10, 14)
    quarterRound(s, 3, 7, 11, 15)
    quarterRound(s, 0, 5, 10, 15)
    quarterRound(s, 1, 6, 11, 12)
    quarterRound(s, 2, 7, 8, 13)
    quarterRound(s, 3, 4, 9, 14)
  }

  const out = Buffer.alloc(32)
  for (let i = 0; i < 4; i++) out.writeUInt32LE(s[i] >>> 0, i * 4)
  for (let i = 0; i < 4; i++) out.writeUInt32LE(s[12 + i] >>> 0, 16 + i * 4)
  return out
}

function xaeadOpen(key, nonce24, data, aad) {
  const subkey = hchacha20(key, nonce24.subarray(0, 16))
  const nonce12 = Buffer.alloc(12)
  nonce24.copy(nonce12, 4, 16, 24)
  return aeadOpen(subkey, nonce12, data, aad)
}

module.exports = { aeadSeal, aeadOpen, xaeadOpen, chacha20Block, chacha20Encrypt, Poly1305 }
