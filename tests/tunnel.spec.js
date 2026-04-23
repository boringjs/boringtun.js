const { describe, test } = require('node:test')
const assert = require('node:assert/strict')
const { WireguardTunnel, generateKeyPair, checkValidKey, getPublicKeyFrom, generatePrivateKey } = require('../index.js')

describe('WireguardTunnel', () => {
  test('Generate key pair', () => {
    const { publicKey, privateKey } = generateKeyPair()

    assert.equal(typeof privateKey, 'string')
    assert.equal(typeof publicKey, 'string')
    assert.notEqual(publicKey, privateKey)

    const privateKeyBuf = Buffer.from(privateKey, 'base64')
    const publicKeyBuf = Buffer.from(publicKey, 'base64')

    assert.equal(privateKeyBuf.length, 32)
    assert.equal(publicKeyBuf.length, 32)

    assert.ok(checkValidKey(privateKey))
    assert.ok(checkValidKey(publicKey))
    assert.ok(checkValidKey(privateKeyBuf))
    assert.ok(checkValidKey(publicKeyBuf))

    assert.equal(getPublicKeyFrom(privateKey), publicKey)
    assert.equal(getPublicKeyFrom(privateKeyBuf), publicKey)
  })

  test('Create tunnel and check keys', () => {
    const privateKey = generatePrivateKey()
    const peerPublicKey = generatePrivateKey()

    const peer = new WireguardTunnel({ privateKey, publicKey: peerPublicKey, keepAlive: 25, index: 1 })

    assert.equal(peer.getPrivateKey(), privateKey)
    assert.equal(peer.getPeerPublicKey(), peerPublicKey)
  })

  test('Wireguard tunnel handshake exchange', () => {
    const { privateKey: privateKey1, publicKey: publicKey1 } = generateKeyPair()
    const { privateKey: privateKey2, publicKey: publicKey2 } = generateKeyPair()

    const peer1 = new WireguardTunnel({ privateKey: privateKey1, publicKey: publicKey2, keepAlive: 25, index: 10 })
    const peer2 = new WireguardTunnel({ privateKey: privateKey2, publicKey: publicKey1, keepAlive: 25, index: 10 })

    const handshake1 = peer1.forceHandshake()
    assert.equal(handshake1.type, WireguardTunnel.WRITE_TO_NETWORK)

    const handshake2 = peer2.write(handshake1.data)
    assert.equal(handshake2.type, WireguardTunnel.WRITE_TO_NETWORK)

    assert.equal(peer1.write(handshake2.data).type, WireguardTunnel.WIREGUARD_DONE)
  })

  test('Wireguard tunnel send ip package', () => {
    const { privateKey: privateKey1, publicKey: publicKey1 } = generateKeyPair()
    const { privateKey: privateKey2, publicKey: publicKey2 } = generateKeyPair()

    const peer1 = new WireguardTunnel({ privateKey: privateKey1, publicKey: publicKey2, keepAlive: 25, index: 500 })
    const peer2 = new WireguardTunnel({ privateKey: privateKey2, publicKey: publicKey1, keepAlive: 25, index: 500 })

    let p1, p2

    assert.equal((p1 = peer1.forceHandshake()).type, WireguardTunnel.WRITE_TO_NETWORK)
    assert.equal((p2 = peer2.read(p1.data)).type, WireguardTunnel.WRITE_TO_NETWORK)
    assert.equal((p1 = peer1.read(p2.data)).type, WireguardTunnel.WRITE_TO_NETWORK)
    assert.equal(peer2.read(p1.data).type, WireguardTunnel.WIREGUARD_DONE)

    const ipv4PacketBuffer = Buffer.from(
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K',
      'base64',
    )

    p1 = peer1.write(ipv4PacketBuffer)
    assert.notDeepEqual(p1.data, ipv4PacketBuffer)
    p2 = peer2.read(p1.data)

    assert.equal(p2.type, WireguardTunnel.WRITE_TO_TUNNEL_IPV4)
    assert.deepEqual(p2.data, ipv4PacketBuffer)
  })
})
