const {generateKeyPair, checkValidKey, getPublicKeyFrom} = require('../index.js')
const {WireguardTunnel, generatePrivateKey} = require("../src/tunnel");

describe('C++ bindings', () => {
  test('Generate key pair', () => {
    const {publicKey, privateKey} = generateKeyPair()

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

  test.skip('Wireguard tunnel pair', () => {
    const {privateKey: privateKey1, publicKey: publicKey1} = generateKeyPair()
    const {privateKey: privateKey2, publicKey: publicKey2} = generateKeyPair()
    const keep_alive = 25
    const preSharedKey = ''
    const index = 10

    const peer1 = new WireguardTunnel(privateKey1, publicKey2, preSharedKey, index)
    const peer2 = new WireguardTunnel(privateKey2, publicKey1, preSharedKey, index)
  })
})
