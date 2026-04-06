const { blake2s } = require('../src/crypto/blake2s.js')
const {
  b2s_hash,
  b2s_hmac,
  b2s_hmac2,
  b2s_keyed_mac_16,
  b2s_keyed_mac_16_2,
  aead_chacha20_seal,
  aead_chacha20_open,
  x25519,
  generateX25519KeyPair,
  getPublicKeyFromPrivate,
  INITIAL_CHAIN_KEY,
  INITIAL_CHAIN_HASH,
} = require('../src/crypto/noise-helpers.js')

describe('BLAKE2s', () => {
  // RFC 7693 Appendix A - BLAKE2s-256 test vector
  test('RFC 7693 unkeyed hash of "abc"', () => {
    const input = Buffer.from('abc')
    const result = blake2s(32, null, input)
    expect(result.toString('hex')).toBe('508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982')
  })

  test('empty input unkeyed', () => {
    const result = blake2s(32, null, Buffer.alloc(0))
    expect(result.toString('hex')).toBe('69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9')
  })

  // RFC 7693 Appendix A - keyed BLAKE2s test vector
  test('RFC 7693 keyed hash', () => {
    // Key: 000102...1f (32 bytes), Input: 000102 (3 bytes), output 32 bytes
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
    const input = Buffer.from(Array.from({ length: 3 }, (_, i) => i))
    const result = blake2s(32, key, input)
    expect(result.toString('hex')).toBe('1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b')
  })

  test('keyed 16-byte output', () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
    const input = Buffer.from(Array.from({ length: 3 }, (_, i) => i))
    const result = blake2s(16, key, input)
    expect(result.length).toBe(16)
  })

  test('keyed 24-byte output', () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
    const input = Buffer.alloc(0)
    const result = blake2s(24, key, input)
    expect(result.length).toBe(24)
  })

  test('large input spans multiple blocks', () => {
    // 200 bytes > 64-byte block size, exercises multi-block path
    const input = Buffer.alloc(200, 0x42)
    const result = blake2s(32, null, input)
    expect(result.length).toBe(32)
    // Deterministic — same input always produces same hash
    const result2 = blake2s(32, null, input)
    expect(result).toEqual(result2)
  })

  test('keyed hash with empty data', () => {
    const key = Buffer.alloc(32, 0xaa)
    const result = blake2s(32, key, Buffer.alloc(0))
    expect(result.length).toBe(32)
  })
})

describe('Noise crypto helpers', () => {
  test('b2s_hash matches BLAKE2s-256', () => {
    const data = Buffer.from('test data')
    const direct = blake2s(32, null, data)
    const via = b2s_hash(data, Buffer.alloc(0))
    expect(via).toEqual(direct)
  })

  test('b2s_hash concatenates two inputs', () => {
    const a = Buffer.from('hello')
    const b = Buffer.from('world')
    const combined = b2s_hash(a, b)
    const manual = blake2s(32, null, Buffer.concat([a, b]))
    expect(combined).toEqual(manual)
  })

  test('b2s_hmac produces 32-byte output', () => {
    const key = Buffer.alloc(32, 0x0b)
    const data = Buffer.from('Hi There')
    const result = b2s_hmac(key, data)
    expect(result.length).toBe(32)
  })

  test('b2s_hmac is deterministic', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('test')
    expect(b2s_hmac(key, data)).toEqual(b2s_hmac(key, data))
  })

  test('b2s_hmac differs from plain hash', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('test')
    const hmacResult = b2s_hmac(key, data)
    const hashResult = b2s_hash(data, Buffer.alloc(0))
    expect(hmacResult).not.toEqual(hashResult)
  })

  test('b2s_hmac2 equals b2s_hmac of concatenated data', () => {
    const key = Buffer.alloc(32, 0xaa)
    const d1 = Buffer.from('part1')
    const d2 = Buffer.from('part2')
    expect(b2s_hmac2(key, d1, d2)).toEqual(b2s_hmac(key, Buffer.concat([d1, d2])))
  })

  test('b2s_keyed_mac_16 produces 16 bytes', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('message')
    const mac = b2s_keyed_mac_16(key, data)
    expect(mac.length).toBe(16)
  })

  test('b2s_keyed_mac_16 is NOT the same as truncated b2s_hash', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('message')
    const mac = b2s_keyed_mac_16(key, data)
    const hashTruncated = b2s_hash(data, Buffer.alloc(0)).subarray(0, 16)
    expect(mac).not.toEqual(hashTruncated)
  })

  test('b2s_keyed_mac_16_2 equals keyed mac of concatenated data', () => {
    const key = Buffer.alloc(32, 0x01)
    const d1 = Buffer.from('part1')
    const d2 = Buffer.from('part2')
    expect(b2s_keyed_mac_16_2(key, d1, d2)).toEqual(b2s_keyed_mac_16(key, Buffer.concat([d1, d2])))
  })

  test('INITIAL_CHAIN_KEY matches HASH(construction)', () => {
    const construction = Buffer.from('Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s')
    const computed = blake2s(32, null, construction)
    expect(computed).toEqual(INITIAL_CHAIN_KEY)
  })

  test('INITIAL_CHAIN_HASH matches HASH(chain_key || identifier)', () => {
    const identifier = Buffer.from('WireGuard v1 zx2c4 Jason@zx2c4.com')
    const computed = blake2s(32, null, Buffer.concat([INITIAL_CHAIN_KEY, identifier]))
    expect(computed).toEqual(INITIAL_CHAIN_HASH)
  })
})

describe('ChaCha20-Poly1305 AEAD', () => {
  test('seal then open roundtrip', () => {
    const key = Buffer.alloc(32, 0x80)
    const plaintext = Buffer.from('Hello, WireGuard!')
    const aad = Buffer.from('additional data')

    const sealed = aead_chacha20_seal(key, 0, plaintext, aad)
    expect(sealed.length).toBe(plaintext.length + 16)

    const opened = aead_chacha20_open(key, 0, sealed, aad)
    expect(opened).toEqual(plaintext)
  })

  test('seal then open with empty plaintext', () => {
    const key = Buffer.alloc(32)
    const aad = Buffer.alloc(32)

    const sealed = aead_chacha20_seal(key, 0, Buffer.alloc(0), aad)
    expect(sealed.length).toBe(16) // just the tag

    const opened = aead_chacha20_open(key, 0, sealed, aad)
    expect(opened.length).toBe(0)
  })

  test('wrong key fails to open', () => {
    const key1 = Buffer.alloc(32, 0x01)
    const key2 = Buffer.alloc(32, 0x02)
    const plaintext = Buffer.from('secret')

    const sealed = aead_chacha20_seal(key1, 0, plaintext, Buffer.alloc(0))
    expect(() => aead_chacha20_open(key2, 0, sealed, Buffer.alloc(0))).toThrow()
  })

  test('wrong counter fails to open', () => {
    const key = Buffer.alloc(32, 0x01)
    const plaintext = Buffer.from('secret')

    const sealed = aead_chacha20_seal(key, 0, plaintext, Buffer.alloc(0))
    expect(() => aead_chacha20_open(key, 1, sealed, Buffer.alloc(0))).toThrow()
  })

  test('tampered ciphertext fails to open', () => {
    const key = Buffer.alloc(32, 0x01)
    const plaintext = Buffer.from('secret')

    const sealed = aead_chacha20_seal(key, 0, plaintext, Buffer.alloc(0))
    sealed[0] ^= 0xff
    expect(() => aead_chacha20_open(key, 0, sealed, Buffer.alloc(0))).toThrow()
  })

  test('different counters produce different ciphertext', () => {
    const key = Buffer.alloc(32, 0x01)
    const plaintext = Buffer.from('same plaintext')

    const s1 = aead_chacha20_seal(key, 0, plaintext, Buffer.alloc(0))
    const s2 = aead_chacha20_seal(key, 1, plaintext, Buffer.alloc(0))
    expect(s1).not.toEqual(s2)
  })
})

describe('X25519 key operations', () => {
  test('generateX25519KeyPair returns 32-byte keys', () => {
    const { privateKey, publicKey } = generateX25519KeyPair()
    expect(privateKey.length).toBe(32)
    expect(publicKey.length).toBe(32)
    expect(privateKey).not.toEqual(publicKey)
  })

  test('getPublicKeyFromPrivate matches generated pair', () => {
    const { privateKey, publicKey } = generateX25519KeyPair()
    const derived = getPublicKeyFromPrivate(privateKey)
    expect(derived).toEqual(publicKey)
  })

  test('DH shared secret is symmetric', () => {
    const kp1 = generateX25519KeyPair()
    const kp2 = generateX25519KeyPair()
    const shared1 = x25519(kp1.privateKey, kp2.publicKey)
    const shared2 = x25519(kp2.privateKey, kp1.publicKey)
    expect(shared1).toEqual(shared2)
  })

  test('different key pairs produce different shared secrets', () => {
    const kp1 = generateX25519KeyPair()
    const kp2 = generateX25519KeyPair()
    const kp3 = generateX25519KeyPair()
    const shared12 = x25519(kp1.privateKey, kp2.publicKey)
    const shared13 = x25519(kp1.privateKey, kp3.publicKey)
    expect(shared12).not.toEqual(shared13)
  })
})
