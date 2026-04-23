const { describe, test } = require('node:test')
const assert = require('node:assert/strict')
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
  test('RFC 7693 unkeyed hash of "abc"', () => {
    const input = Buffer.from('abc')
    const result = blake2s(32, null, input)
    assert.equal(result.toString('hex'), '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982')
  })

  test('empty input unkeyed', () => {
    const result = blake2s(32, null, Buffer.alloc(0))
    assert.equal(result.toString('hex'), '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9')
  })

  test('RFC 7693 keyed hash', () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
    const input = Buffer.from(Array.from({ length: 3 }, (_, i) => i))
    const result = blake2s(32, key, input)
    assert.equal(result.toString('hex'), '1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b')
  })

  test('keyed 16-byte output', () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
    const input = Buffer.from(Array.from({ length: 3 }, (_, i) => i))
    const result = blake2s(16, key, input)
    assert.equal(result.length, 16)
  })

  test('keyed 24-byte output', () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
    const input = Buffer.alloc(0)
    const result = blake2s(24, key, input)
    assert.equal(result.length, 24)
  })

  test('large input spans multiple blocks', () => {
    const input = Buffer.alloc(200, 0x42)
    const result = blake2s(32, null, input)
    assert.equal(result.length, 32)
    const result2 = blake2s(32, null, input)
    assert.deepEqual(result, result2)
  })

  test('keyed hash with empty data', () => {
    const key = Buffer.alloc(32, 0xaa)
    const result = blake2s(32, key, Buffer.alloc(0))
    assert.equal(result.length, 32)
  })
})

describe('Noise crypto helpers', () => {
  test('b2s_hash matches BLAKE2s-256', () => {
    const data = Buffer.from('test data')
    const direct = blake2s(32, null, data)
    const via = b2s_hash(data, Buffer.alloc(0))
    assert.deepEqual(via, direct)
  })

  test('b2s_hash concatenates two inputs', () => {
    const a = Buffer.from('hello')
    const b = Buffer.from('world')
    const combined = b2s_hash(a, b)
    const manual = blake2s(32, null, Buffer.concat([a, b]))
    assert.deepEqual(combined, manual)
  })

  test('b2s_hmac produces 32-byte output', () => {
    const key = Buffer.alloc(32, 0x0b)
    const data = Buffer.from('Hi There')
    const result = b2s_hmac(key, data)
    assert.equal(result.length, 32)
  })

  test('b2s_hmac is deterministic', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('test')
    assert.deepEqual(b2s_hmac(key, data), b2s_hmac(key, data))
  })

  test('b2s_hmac differs from plain hash', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('test')
    const hmacResult = b2s_hmac(key, data)
    const hashResult = b2s_hash(data, Buffer.alloc(0))
    assert.notDeepEqual(hmacResult, hashResult)
  })

  test('b2s_hmac2 equals b2s_hmac of concatenated data', () => {
    const key = Buffer.alloc(32, 0xaa)
    const d1 = Buffer.from('part1')
    const d2 = Buffer.from('part2')
    assert.deepEqual(b2s_hmac2(key, d1, d2), b2s_hmac(key, Buffer.concat([d1, d2])))
  })

  test('b2s_keyed_mac_16 produces 16 bytes', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('message')
    const mac = b2s_keyed_mac_16(key, data)
    assert.equal(mac.length, 16)
  })

  test('b2s_keyed_mac_16 is NOT the same as truncated b2s_hash', () => {
    const key = Buffer.alloc(32, 0x01)
    const data = Buffer.from('message')
    const mac = b2s_keyed_mac_16(key, data)
    const hashTruncated = b2s_hash(data, Buffer.alloc(0)).subarray(0, 16)
    assert.notDeepEqual(mac, hashTruncated)
  })

  test('b2s_keyed_mac_16_2 equals keyed mac of concatenated data', () => {
    const key = Buffer.alloc(32, 0x01)
    const d1 = Buffer.from('part1')
    const d2 = Buffer.from('part2')
    assert.deepEqual(b2s_keyed_mac_16_2(key, d1, d2), b2s_keyed_mac_16(key, Buffer.concat([d1, d2])))
  })

  test('INITIAL_CHAIN_KEY matches HASH(construction)', () => {
    const construction = Buffer.from('Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s')
    const computed = blake2s(32, null, construction)
    assert.deepEqual(computed, INITIAL_CHAIN_KEY)
  })

  test('INITIAL_CHAIN_HASH matches HASH(chain_key || identifier)', () => {
    const identifier = Buffer.from('WireGuard v1 zx2c4 Jason@zx2c4.com')
    const computed = blake2s(32, null, Buffer.concat([INITIAL_CHAIN_KEY, identifier]))
    assert.deepEqual(computed, INITIAL_CHAIN_HASH)
  })
})

describe('ChaCha20-Poly1305 AEAD', () => {
  test('seal then open roundtrip', () => {
    const key = Buffer.alloc(32, 0x80)
    const plaintext = Buffer.from('Hello, WireGuard!')
    const aad = Buffer.from('additional data')

    const sealed = aead_chacha20_seal(key, 0, plaintext, aad)
    assert.equal(sealed.length, plaintext.length + 16)

    const opened = aead_chacha20_open(key, 0, sealed, aad)
    assert.deepEqual(opened, plaintext)
  })

  test('seal then open with empty plaintext', () => {
    const key = Buffer.alloc(32)
    const aad = Buffer.alloc(32)

    const sealed = aead_chacha20_seal(key, 0, Buffer.alloc(0), aad)
    assert.equal(sealed.length, 16)

    const opened = aead_chacha20_open(key, 0, sealed, aad)
    assert.equal(opened.length, 0)
  })

  test('wrong key fails to open', () => {
    const key1 = Buffer.alloc(32, 0x01)
    const key2 = Buffer.alloc(32, 0x02)
    const plaintext = Buffer.from('secret')

    const sealed = aead_chacha20_seal(key1, 0, plaintext, Buffer.alloc(0))
    assert.throws(() => aead_chacha20_open(key2, 0, sealed, Buffer.alloc(0)))
  })

  test('wrong counter fails to open', () => {
    const key = Buffer.alloc(32, 0x01)
    const plaintext = Buffer.from('secret')

    const sealed = aead_chacha20_seal(key, 0, plaintext, Buffer.alloc(0))
    assert.throws(() => aead_chacha20_open(key, 1, sealed, Buffer.alloc(0)))
  })

  test('tampered ciphertext fails to open', () => {
    const key = Buffer.alloc(32, 0x01)
    const plaintext = Buffer.from('secret')

    const sealed = aead_chacha20_seal(key, 0, plaintext, Buffer.alloc(0))
    sealed[0] ^= 0xff
    assert.throws(() => aead_chacha20_open(key, 0, sealed, Buffer.alloc(0)))
  })

  test('different counters produce different ciphertext', () => {
    const key = Buffer.alloc(32, 0x01)
    const plaintext = Buffer.from('same plaintext')

    const s1 = aead_chacha20_seal(key, 0, plaintext, Buffer.alloc(0))
    const s2 = aead_chacha20_seal(key, 1, plaintext, Buffer.alloc(0))
    assert.notDeepEqual(s1, s2)
  })
})

describe('X25519 key operations', () => {
  test('generateX25519KeyPair returns 32-byte keys', () => {
    const { privateKey, publicKey } = generateX25519KeyPair()
    assert.equal(privateKey.length, 32)
    assert.equal(publicKey.length, 32)
    assert.notDeepEqual(privateKey, publicKey)
  })

  test('getPublicKeyFromPrivate matches generated pair', () => {
    const { privateKey, publicKey } = generateX25519KeyPair()
    const derived = getPublicKeyFromPrivate(privateKey)
    assert.deepEqual(derived, publicKey)
  })

  test('DH shared secret is symmetric', () => {
    const kp1 = generateX25519KeyPair()
    const kp2 = generateX25519KeyPair()
    const shared1 = x25519(kp1.privateKey, kp2.publicKey)
    const shared2 = x25519(kp2.privateKey, kp1.publicKey)
    assert.deepEqual(shared1, shared2)
  })

  test('different key pairs produce different shared secrets', () => {
    const kp1 = generateX25519KeyPair()
    const kp2 = generateX25519KeyPair()
    const kp3 = generateX25519KeyPair()
    const shared12 = x25519(kp1.privateKey, kp2.publicKey)
    const shared13 = x25519(kp1.privateKey, kp3.publicKey)
    assert.notDeepEqual(shared12, shared13)
  })
})
