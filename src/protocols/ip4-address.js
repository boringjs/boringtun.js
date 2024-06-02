class IP4Address {
  #ipBuffer = Buffer.alloc(4)
  #mask = 32

  /**
   * @param {Buffer|number|string|IP4Address} init
   * @param {number} [offset]
   */
  constructor(init = 0, offset = 0) {
    if (typeof offset !== 'number' || Number.isNaN(offset)) {
      throw new TypeError('Invalid type of offset')
    }

    if (init instanceof Buffer) {
      init.copy(this.#ipBuffer, 0, offset, offset + 4)
      return
    }

    if (init instanceof IP4Address) {
      init.toBuffer().copy(this.#ipBuffer, 0, offset, offset + 4)
      return
    }

    if (typeof init === 'string') {
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(init) && !/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(init)) {
        throw new TypeError('invalid ipv4 format')
      }

      const [ip, mask] = init.split('/')

      const tmp = ip.split('.').map((a) => parseInt(a, 10) % 256)

      if (mask) {
        this.#mask = parseInt(mask)
      }

      this.#ipBuffer[0] = tmp[0]
      this.#ipBuffer[1] = tmp[1]
      this.#ipBuffer[2] = tmp[2]
      this.#ipBuffer[3] = tmp[3]

      return
    }

    if (typeof init === 'number') {
      this.#ipBuffer[3] = init & 0xff
      this.#ipBuffer[2] = (init >> 8) & 0xff
      this.#ipBuffer[1] = (init >> 16) & 0xff
      this.#ipBuffer[0] = (init >> 24) & 0xff

      return
    }

    throw new TypeError('Cannot create ip from params')
  }

  match(ip) {
    const ipBuffer = (ip instanceof IP4Address ? ip : new IP4Address(ip)).toBuffer()

    for (let i = 0; i < this.#mask; i++) {
      const byte = (i - (i % 8)) / 8
      const shift = 7 - (i % 8)
      const mask = this.#ipBuffer[byte]
      const value = ipBuffer[byte]
      const test = ((1 << shift) & mask) === ((1 << shift) & value)
      if (!test) {
        return false
      }
    }

    return true
  }

  toString() {
    return `${this.#ipBuffer[0]}.${this.#ipBuffer[1]}.${this.#ipBuffer[2]}.${this.#ipBuffer[3]}`
  }

  toNumber() {
    return this.#ipBuffer[0] * 16777216 + this.#ipBuffer[1] * 65536 + this.#ipBuffer[2] * 256 + this.#ipBuffer[3]
  }

  toBuffer() {
    const result = Buffer.allocUnsafe(4)
    this.#ipBuffer.copy(result)
    return result
  }

  copy() {
    return new IP4Address(this.#ipBuffer)
  }
}

module.exports = IP4Address
