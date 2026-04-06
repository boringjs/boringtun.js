const { WireguardTunnel, generateKeyPair, checkValidKey, getPublicKeyFrom, generatePrivateKey } = require('../index.js')

describe('WireguardTunnel', () => {
  test('Generate key pair', () => {
    const { publicKey, privateKey } = generateKeyPair()

    expect(typeof privateKey).toBe('string')
    expect(typeof publicKey).toBe('string')
    expect(publicKey).not.toBe(privateKey)

    const privateKeyBuf = Buffer.from(privateKey, 'base64')
    const publicKeyBuf = Buffer.from(publicKey, 'base64')

    expect(privateKeyBuf.length).toBe(32)
    expect(publicKeyBuf.length).toBe(32)

    expect(checkValidKey(privateKey)).toBeTruthy()
    expect(checkValidKey(publicKey)).toBeTruthy()
    expect(checkValidKey(privateKeyBuf)).toBeTruthy()
    expect(checkValidKey(publicKeyBuf)).toBeTruthy()

    expect(getPublicKeyFrom(privateKey)).toBe(publicKey)
    expect(getPublicKeyFrom(privateKeyBuf)).toBe(publicKey)
  })

  test('Create tunnel and check keys', () => {
    const privateKey = generatePrivateKey()
    const peerPublicKey = generatePrivateKey()

    const peer = new WireguardTunnel({ privateKey, publicKey: peerPublicKey, keepAlive: 25, index: 1 })

    expect(peer.getPrivateKey()).toBe(privateKey)

    expect(peer.getPeerPublicKey()).toBe(peerPublicKey)
  })

  test('Wireguard tunnel handshake exchange', () => {
    const { privateKey: privateKey1, publicKey: publicKey1 } = generateKeyPair()
    const { privateKey: privateKey2, publicKey: publicKey2 } = generateKeyPair()

    const peer1 = new WireguardTunnel({ privateKey: privateKey1, publicKey: publicKey2, keepAlive: 25, index: 10 })
    const peer2 = new WireguardTunnel({ privateKey: privateKey2, publicKey: publicKey1, keepAlive: 25, index: 10 })

    const handshake1 = peer1.forceHandshake()

    expect(handshake1.type).toBe(WireguardTunnel.WRITE_TO_NETWORK)

    const handshake2 = peer2.write(handshake1.data)

    expect(handshake2.type).toBe(WireguardTunnel.WRITE_TO_NETWORK)

    expect(peer1.write(handshake2.data).type).toBe(WireguardTunnel.WIREGUARD_DONE)
  })

  test('Wireguard tunnel send ip package', () => {
    const { privateKey: privateKey1, publicKey: publicKey1 } = generateKeyPair()
    const { privateKey: privateKey2, publicKey: publicKey2 } = generateKeyPair()

    const peer1 = new WireguardTunnel({ privateKey: privateKey1, publicKey: publicKey2, keepAlive: 25, index: 500 })
    const peer2 = new WireguardTunnel({ privateKey: privateKey2, publicKey: publicKey1, keepAlive: 25, index: 500 })

    let p1, p2

    expect((p1 = peer1.forceHandshake()).type).toBe(WireguardTunnel.WRITE_TO_NETWORK)
    expect((p2 = peer2.read(p1.data)).type).toBe(WireguardTunnel.WRITE_TO_NETWORK)
    expect((p1 = peer1.read(p2.data)).type).toBe(WireguardTunnel.WRITE_TO_NETWORK)
    expect(peer2.read(p1.data).type).toBe(WireguardTunnel.WIREGUARD_DONE)

    const ipv4PacketBuffer = Buffer.from(
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K',
      'base64',
    )

    p1 = peer1.write(ipv4PacketBuffer)
    expect(p1.data).not.toEqual(ipv4PacketBuffer)
    p2 = peer2.read(p1.data)

    expect(p2.type).toBe(WireguardTunnel.WRITE_TO_TUNNEL_IPV4)
    expect(p2.data).toEqual(ipv4PacketBuffer)
  })
})
