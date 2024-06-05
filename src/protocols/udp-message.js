const { PROTOCOLS } = require('./constants.js')
const DNSMessage = require('./dns-message.js')

/*
 https://www.ietf.org/rfc/rfc768.txt

 pseudo header:
 0      7 8     15 16    23 24    31
 +--------+--------+--------+--------+
 |          source address           |
 +--------+--------+--------+--------+
 |        destination address        |
 +--------+--------+--------+--------+
 |  zero  |protocol|   UDP length    |
 +--------+--------+--------+--------+

udp:
  0      7 8     15 16    23 24    31
 +--------+--------+--------+--------+
 |     Source      |   Destination   |
 |      Port       |      Port       |
 +--------+--------+--------+--------+
 |                 |                 |
 |     Length      |    Checksum     |
 +--------+--------+--------+--------+
 |
 |          data octets ...
 +---------------- ...

 */

class UDPMessage {
  #sourcePort = 0
  #destinationPort = 0
  #length = 0
  #checksum = 0
  #data = null
  // pseudo header
  #sourceIP = null
  #destinationIP = null

  constructor(input) {
    if (!input) {
      this.#data = Buffer.alloc(0)
      return
    }
    if (input instanceof Buffer) {
      this.#parse(input)
      return
    }

    if (typeof input === 'object') {
      const { sourceIP, destinationIP, sourcePort, destinationPort, udpData } = input

      this.#sourceIP = sourceIP
      this.#destinationIP = destinationIP
      this.#sourcePort = sourcePort
      this.#destinationPort = destinationPort
      this.#data = udpData
      this.#length = udpData.length + 8
      this.#checksum = this.#calculateUDPChecksum()
    }
  }

  #calculateUDPChecksum() {
    let checksum = 0

    let buf = this.#sourceIP.toBuffer()
    checksum += buf.readUInt16BE(0) & 0xffff
    checksum += buf.readUInt16BE(2) & 0xffff

    buf = this.#destinationIP.toBuffer()
    checksum += buf.readUInt16BE(0) & 0xffff
    checksum += buf.readUInt16BE(2) & 0xffff

    checksum += 0 // checksum field
    checksum += PROTOCOLS.UDP
    checksum += this.#length
    checksum += this.#sourcePort
    checksum += this.#destinationPort
    checksum += this.#length

    for (let i = 0; i < this.#data.length; i += 2) {
      if (i + 1 < this.#data.length) {
        checksum += this.#data.readUInt16BE(i)
      } else {
        // If the data length is odd, pad with a zero byte for checksum calculation
        checksum += this.#data.readUInt8(i) << 8
      }
    }

    while (checksum >> 16) {
      checksum = (checksum & 0xffff) + (checksum >> 16)
    }

    checksum = ~checksum & 0xffff
    return checksum === 0 ? 0xffff : checksum
  }

  debugView() {
    // todo remove
    return {
      sourcePort: this.#sourcePort,
      destinationPort: this.#destinationPort,
      length: this.#length,
      checksum: this.#checksum,
      data: this.#data.toString('base64'),
    }
  }

  get sourcePort() {
    return this.#sourcePort
  }

  get destinationPort() {
    return this.#destinationPort
  }

  get destinationIP() {
    return this.#destinationIP
  }

  get sourceIP() {
    return this.#sourceIP
  }

  /**
   * @return {Buffer}
   */
  get dataCopy() {
    return Buffer.from(this.#data)
  }

  /**
   * @return {Buffer}
   */
  get data() {
    return this.#data
  }

  get checksum() {
    return this.#checksum
  }

  /**
   * @param {Buffer|String|Number} v
   */
  set sourceIP(v) {
    this.#sourceIP = v
  }

  /**
   * @param {Buffer|String|Number} v
   */
  set destinationIP(v) {
    this.#destinationIP = v
  }

  #parse(buffer) {
    let offset = 0
    this.#sourcePort = buffer.readUInt16BE(offset)
    offset += 2
    this.#destinationPort = buffer.readUInt16BE(offset)
    offset += 2
    this.#length = buffer.readUInt16BE(offset)
    offset += 2
    this.#checksum = buffer.readUInt16BE(offset)
    offset += 2
    this.#data = buffer.slice(offset, this.#length) // todo copy

    return this
  }

  toBuffer() {
    const buffer = Buffer.alloc(8 + this.#data.length)

    let offset = 0
    buffer.writeUInt16BE(this.#sourcePort, offset)
    offset += 2
    buffer.writeUInt16BE(this.#destinationPort, offset)
    offset += 2
    buffer.writeUInt16BE(this.#length, offset)
    offset += 2
    buffer.writeUInt16BE(this.#checksum, offset)
    offset += 2
    this.#data.copy(buffer, offset, 0, this.#data.length)

    return buffer
  }

  isDnsRequest() {
    if (this.#destinationPort !== 53) {
      return false
    }

    if (this.#data.length < 12) {
      return false
    }

    return (this.#data[2] & 0x80) === 0
  }

  isDnsResponse() {
    if (this.#sourcePort !== 53) {
      return false
    }

    if (this.#data.length < 12) {
      return false
    }

    return (this.#data[2] & 0x80) === 1
  }

  getDNSMessage() {
    if(this.isDnsRequest() || this.isDnsResponse()){
      return new DNSMessage(this.#data)
    }

    return null
  }
}

module.exports = UDPMessage
