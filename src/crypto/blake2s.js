'use strict'

// BLAKE2s implementation per RFC 7693
// Supports keyed hashing and variable output length (1-32 bytes)

// Initialization vector (same as SHA-256)
const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
])

// Message schedule permutation (sigma)
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

// Working state for compression
const v = new Uint32Array(16)
const m = new Uint32Array(16)

function G(a, b, c, d, x, y) {
  v[a] = (v[a] + v[b] + x) | 0
  v[d] = v[d] ^ v[a]
  v[d] = (v[d] >>> 16) | (v[d] << 16)

  v[c] = (v[c] + v[d]) | 0
  v[b] = v[b] ^ v[c]
  v[b] = (v[b] >>> 12) | (v[b] << 20)

  v[a] = (v[a] + v[b] + y) | 0
  v[d] = v[d] ^ v[a]
  v[d] = (v[d] >>> 8) | (v[d] << 24)

  v[c] = (v[c] + v[d]) | 0
  v[b] = v[b] ^ v[c]
  v[b] = (v[b] >>> 7) | (v[b] << 25)
}

function compress(h, block, t, last) {
  // Init working variables
  for (let i = 0; i < 8; i++) {
    v[i] = h[i]
    v[i + 8] = IV[i]
  }

  v[12] ^= t // low 32 bits of counter
  v[13] ^= 0 // high 32 bits of counter (we stay < 2^32)
  if (last) {
    v[14] = ~v[14] // invert all bits for last block
  }

  // Load message block as 16 little-endian 32-bit words
  for (let i = 0; i < 16; i++) {
    const off = i * 4
    m[i] = block[off] | (block[off + 1] << 8) | (block[off + 2] << 16) | (block[off + 3] << 24)
  }

  // 10 rounds of mixing
  for (let round = 0; round < 10; round++) {
    const s = SIGMA[round]
    G(0, 4, 8, 12, m[s[0]], m[s[1]])
    G(1, 5, 9, 13, m[s[2]], m[s[3]])
    G(2, 6, 10, 14, m[s[4]], m[s[5]])
    G(3, 7, 11, 15, m[s[6]], m[s[7]])
    G(0, 5, 10, 15, m[s[8]], m[s[9]])
    G(1, 6, 11, 12, m[s[10]], m[s[11]])
    G(2, 7, 8, 13, m[s[12]], m[s[13]])
    G(3, 4, 9, 14, m[s[14]], m[s[15]])
  }

  // Finalize
  for (let i = 0; i < 8; i++) {
    h[i] ^= v[i] ^ v[i + 8]
  }
}

/**
 * BLAKE2s hash with optional key and configurable output length.
 * @param {number} outLen - Output length in bytes (1-32)
 * @param {Uint8Array|Buffer|null} key - Optional key (0-32 bytes)
 * @param {Uint8Array|Buffer} input - Data to hash
 * @returns {Buffer} - Hash output
 */
function blake2s(outLen, key, input) {
  const keyLen = key ? key.length : 0

  // Parameter block: fan-out=1, depth=1, all others 0
  const h = new Uint32Array(8)
  for (let i = 0; i < 8; i++) h[i] = IV[i]
  // h[0] XOR (outLen | keyLen<<8 | 0x01<<16 | 0x01<<24)
  h[0] ^= 0x01010000 ^ (keyLen << 8) ^ outLen

  let t = 0
  const block = new Uint8Array(64)

  // If keyed, the first block is the key padded to 64 bytes
  let pos = 0
  let dataLen = input.length
  let dataOff = 0

  if (keyLen > 0) {
    block.set(key)
    // rest already zeroed
    t = 64
    // If there's no more data, this is the last block
    if (dataLen === 0) {
      compress(h, block, t, true)
    } else {
      compress(h, block, t, false)
    }
    block.fill(0)
    pos = 0
  }

  // Process data blocks
  if (dataLen > 0) {
    // Process all complete blocks except the last one
    while (dataOff + 64 < dataLen) {
      // Copy next 64 bytes
      for (let i = 0; i < 64; i++) block[i] = input[dataOff + i]
      dataOff += 64
      t += 64
      compress(h, block, t, false)
    }

    // Last block (may be partial)
    block.fill(0)
    const remaining = dataLen - dataOff
    for (let i = 0; i < remaining; i++) block[i] = input[dataOff + i]
    t += remaining
    compress(h, block, t, true)
  } else if (keyLen === 0) {
    // Empty input with no key - compress an empty padded block
    t = 0
    compress(h, block, t, true)
  }

  // Extract output
  const out = Buffer.alloc(outLen)
  for (let i = 0; i < outLen; i++) {
    out[i] = (h[i >> 2] >> (8 * (i & 3))) & 0xff
  }
  return out
}

module.exports = { blake2s }
