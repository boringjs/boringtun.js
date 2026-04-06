'use strict'

const crypto = require('crypto')
const { blake2s } = require('./blake2s.js')
const { aeadSeal, aeadOpen, xaeadOpen } = require('./chacha20poly1305.js')

// --- BLAKE2s-based helpers (from handshake.rs) ---

const BLAKE2S_BLOCK_SIZE = 64

/** BLAKE2s-256 hash of concatenated inputs */
function b2s_hash(data1, data2) {
  if (data2 && data2.length > 0) {
    return blake2s(32, null, Buffer.concat([data1, data2]))
  }
  return blake2s(32, null, data1)
}

/** RFC 2104 HMAC-BLAKE2s-256 (NOT keyed BLAKE2s — uses standard HMAC construction) */
function b2s_hmac(key, data1) {
  let k = key
  if (k.length > BLAKE2S_BLOCK_SIZE) {
    k = blake2s(32, null, k)
  }
  const padded = Buffer.alloc(BLAKE2S_BLOCK_SIZE)
  k.copy(padded)

  const ipad = Buffer.alloc(BLAKE2S_BLOCK_SIZE)
  const opad = Buffer.alloc(BLAKE2S_BLOCK_SIZE)
  for (let i = 0; i < BLAKE2S_BLOCK_SIZE; i++) {
    ipad[i] = padded[i] ^ 0x36
    opad[i] = padded[i] ^ 0x5c
  }

  const inner = blake2s(32, null, Buffer.concat([ipad, data1]))
  return blake2s(32, null, Buffer.concat([opad, inner]))
}

/** HMAC-BLAKE2s-256 with two data inputs concatenated */
function b2s_hmac2(key, data1, data2) {
  return b2s_hmac(key, Buffer.concat([data1, data2]))
}

/** Keyed BLAKE2s with 16-byte output (uses built-in BLAKE2s keying, NOT HMAC) */
function b2s_keyed_mac_16(key, data1) {
  return blake2s(16, key, data1)
}

/** Keyed BLAKE2s with 16-byte output, two data inputs */
function b2s_keyed_mac_16_2(key, data1, data2) {
  const combined = Buffer.concat([data1, data2])
  return blake2s(16, key, combined)
}

/** Keyed BLAKE2s with 24-byte output */
function b2s_mac_24(key, data1) {
  return blake2s(24, key, data1)
}

// --- ChaCha20-Poly1305 AEAD ---

/** Build 12-byte nonce: first 4 bytes zero, last 8 bytes = counter as LE uint64 */
function makeNonce(counter) {
  const nonce = Buffer.alloc(12)
  nonce.writeUInt32LE(counter & 0xffffffff, 4)
  nonce.writeUInt32LE(Math.floor(counter / 0x100000000), 8)
  return nonce
}

/** ChaCha20-Poly1305 encrypt. Returns Buffer of ciphertext + 16-byte tag */
function aead_chacha20_seal(key, counter, plaintext, aad) {
  const nonce = makeNonce(counter)
  return aeadSeal(key, nonce, plaintext, aad)
}

/** ChaCha20-Poly1305 decrypt. Returns plaintext Buffer, or throws on auth failure */
function aead_chacha20_open(key, counter, data, aad) {
  const nonce = makeNonce(counter)
  return aeadOpen(key, nonce, data, aad)
}

// --- X25519 key helpers ---

const PKCS8_HEADER = Buffer.from('302e020100300506032b656e04220420', 'hex')
const SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex')

function importPrivateKey(raw) {
  const der = Buffer.concat([PKCS8_HEADER, raw])
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
}

function importPublicKey(raw) {
  const der = Buffer.concat([SPKI_HEADER, raw])
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
}

function exportPrivateKeyRaw(keyObj) {
  const der = keyObj.export({ type: 'pkcs8', format: 'der' })
  return Buffer.from(der.subarray(16, 48))
}

function exportPublicKeyRaw(keyObj) {
  const der = keyObj.export({ type: 'spki', format: 'der' })
  return Buffer.from(der.subarray(12, 44))
}

function x25519(privateKeyRaw, publicKeyRaw) {
  const privKey = importPrivateKey(privateKeyRaw)
  const pubKey = importPublicKey(publicKeyRaw)
  return crypto.diffieHellman({ privateKey: privKey, publicKey: pubKey })
}

function generateX25519KeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519')
  return {
    privateKey: exportPrivateKeyRaw(privateKey),
    publicKey: exportPublicKeyRaw(publicKey),
  }
}

function getPublicKeyFromPrivate(privateKeyRaw) {
  const privKey = importPrivateKey(privateKeyRaw)
  const pubKey = crypto.createPublicKey(privKey)
  return exportPublicKeyRaw(pubKey)
}

// --- XChaCha20-Poly1305 (for cookie replies) ---

function xchacha20_open(key, nonce24, ciphertext, aad) {
  return xaeadOpen(key, nonce24, ciphertext, aad)
}

// --- Precomputed Noise protocol constants ---

const INITIAL_CHAIN_KEY = Buffer.from([
  96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248, 114, 119, 245, 45, 56,
  209, 152, 139, 120, 205, 54,
])

const INITIAL_CHAIN_HASH = Buffer.from([
  34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34, 147, 232, 183, 14, 225,
  156, 101, 186, 7, 158, 243,
])

const LABEL_MAC1 = Buffer.from('mac1----')
const LABEL_COOKIE = Buffer.from('cookie--')

module.exports = {
  b2s_hash,
  b2s_hmac,
  b2s_hmac2,
  b2s_keyed_mac_16,
  b2s_keyed_mac_16_2,
  b2s_mac_24,
  aead_chacha20_seal,
  aead_chacha20_open,
  xchacha20_open,
  x25519,
  generateX25519KeyPair,
  getPublicKeyFromPrivate,
  importPrivateKey,
  importPublicKey,
  exportPrivateKeyRaw,
  exportPublicKeyRaw,
  makeNonce,
  INITIAL_CHAIN_KEY,
  INITIAL_CHAIN_HASH,
  LABEL_MAC1,
  LABEL_COOKIE,
}
