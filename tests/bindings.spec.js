const {
  WireguardTunnel,
  setLoggingFunction,
  generateKeyPair,
  checkValidKey,
  getPublicKeyFrom,
  generatePrivateKey,
  WRITE_TO_NETWORK,
  WIREGUARD_DONE
} = require('../index.js')


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

  test('Create tunnel', () => {
    const privateKey = generatePrivateKey()
    const peerPublicKey = generatePrivateKey()

    const peer = new WireguardTunnel(privateKey, peerPublicKey, '', 25, 1)

    expect(peer.getPrivateKey()).toBe(privateKey)

    expect(peer.getPublicKey()).toBe(peerPublicKey)
  })
})
