const IPV4Address = require('./ip4-address.js')
const { PROTOCOLS, TCP } = require('./constants.js')

/*
 https://www.ietf.org/rfc/rfc793.txt
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Source Port          |       Destination Port        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Sequence Number                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Acknowledgment Number                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Data |           |U|A|P|R|S|F|                               |
 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 |       |           |G|K|H|T|N|N|                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |         Urgent Pointer        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             data                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

class TCPMessage {
  #sourcePort = 0
  #destinationPort = 0
  #sequenceNumber = 0
  #acknowledgmentNumber = 0
  #dataOffset = 0
  #URG = false
  #ACK = false
  #PSH = false
  #RST = false
  #SYN = false
  #FIN = false
  #window = 0
  #checksum = 0
  #urgentPointer = 0
  #options = Buffer.alloc(0)
  #padding = 0
  #data = Buffer.alloc(0)
  // pseudo header
  #sourceIP = null
  #destinationIP = null

  constructor(input = null) {
    if (input === null) {
      return
    }

    if (input instanceof Buffer) {
      this.#parse(input)
      return
    }

    if (typeof input === 'object') {
      this.sourceIP = input.sourceIP
      this.destinationIP = input.destinationIP

      this.#sourcePort = input.sourcePort
      this.#destinationPort = input.destinationPort
      this.#sequenceNumber = input.sequenceNumber || 0
      this.#acknowledgmentNumber = input.acknowledgmentNumber || 0
      this.#urgentPointer = input.urgentPointer || 0
      this.#URG = input.URG || false
      this.#ACK = input.ACK || false
      this.#PSH = input.PSH || false
      this.#RST = input.RST || false
      this.#SYN = input.SYN || false
      this.#FIN = input.FIN || false
      this.#window = input.window || 0
      this.#options = input.options || Buffer.alloc(0) // todo copy

      const data = typeof input.data === 'string' ? Buffer.from(input.data) : input.data // todo copy
      this.#data = data || Buffer.alloc(0)

      return
    }

    throw new TypeError('Invalid input parameter')
  }

  debugView() {
    return {
      source: `${this.#sourceIP}:${this.#sourcePort}`,
      destination: `${this.#destinationIP}:${this.#destinationPort}`,
      sequenceNumber: this.#sequenceNumber,
      acknowledgmentNumber: this.#acknowledgmentNumber,
      dataOffset: this.#dataOffset,
      URG: this.#URG,
      ACK: this.#ACK,
      PSH: this.#PSH,
      RST: this.#RST,
      SYN: this.#SYN,
      FIN: this.#FIN,
      window: this.#window,
      checksum: this.#checksum,
      urgentPointer: this.#urgentPointer,
      padding: this.#padding,
      dataLen: this.#data.length,
      data: this.#data.toString('hex'),
    }
  }

  #calculateTCPChecksum(buffer) {
    if (!this.#sourceIP || !this.#destinationIP) {
      return 0
    }

    let checksum = 0

    let buf = this.#sourceIP.toBuffer()
    checksum += buf.readUInt16BE(0) & 0xffff
    checksum += buf.readUInt16BE(2) & 0xffff

    buf = this.#destinationIP.toBuffer()
    checksum += buf.readUInt16BE(0) & 0xffff
    checksum += buf.readUInt16BE(2) & 0xffff

    checksum += PROTOCOLS[TCP] // tcp protocol
    checksum += buffer.length

    for (let i = 0; i < buffer.length; i += 2) {
      if (i + 1 < buffer.length) {
        checksum += buffer.readUInt16BE(i)
      } else {
        // If the data length is odd, pad with a zero byte for checksum calculation
        checksum += buffer.readUInt8(i) << 8
      }
    }

    while (checksum >> 16) {
      checksum = (checksum & 0xffff) + (checksum >> 16)
    }

    checksum = ~checksum & 0xffff
    return checksum === 0 ? 0xffff : checksum
  }

  /**
   * @param {Buffer} buffer
   */
  #parse(buffer) {
    let offset = 0
    this.#sourcePort = buffer.readUInt16BE(offset)
    offset += 2
    this.#destinationPort = buffer.readUInt16BE(offset)
    offset += 2 // 4
    this.#sequenceNumber = buffer.readUInt32BE(offset)
    offset += 4 // 8
    this.#acknowledgmentNumber = buffer.readUInt32BE(offset)
    offset += 4 // 12
    this.#dataOffset = (buffer.readUInt8(offset) >> 4) * 4
    offset++

    const flags = buffer.readUint8(offset)
    this.#URG = Boolean(flags & 0b00100000)
    this.#ACK = Boolean(flags & 0b00010000)
    this.#PSH = Boolean(flags & 0b00001000)
    this.#RST = Boolean(flags & 0b00000100)
    this.#SYN = Boolean(flags & 0b00000010)
    this.#FIN = Boolean(flags & 0b00000001)
    offset++
    this.#window = buffer.readUint16BE(offset)
    offset += 2
    this.#checksum = buffer.readUint16BE(offset)
    offset += 2
    this.#urgentPointer = buffer.readUint16BE(offset)
    offset += 2

    if (this.#dataOffset > 20) {
      const optionsLength = this.#dataOffset - offset
      this.#options = Buffer.alloc(optionsLength)
      buffer.copy(this.#options, 0, offset, offset + optionsLength)
      offset += optionsLength
    } else {
      this.#options = Buffer.alloc(0)
    }

    this.#data = buffer.slice(offset)
  }

  toBuffer() {
    let offset = 0
    const optionsLength = this.#options.length
    const length = 20 + optionsLength + this.#data.length
    const buffer = Buffer.alloc(length, 0)

    buffer.writeUInt16BE(this.#sourcePort, offset)
    offset += 2
    buffer.writeUInt16BE(this.#destinationPort, offset)
    offset += 2
    buffer.writeUInt32BE(this.#sequenceNumber, offset)
    offset += 4
    buffer.writeUInt32BE(this.#acknowledgmentNumber, offset)
    offset += 4

    this.#dataOffset = 20 + this.#options.length

    const dataOffset = (this.#dataOffset / 4) << 4
    buffer.writeUInt8(dataOffset, offset)
    offset++

    const flags =
      (Number(this.#URG) << 5) +
      (Number(this.#ACK) << 4) +
      (Number(this.#PSH) << 3) +
      (Number(this.#RST) << 2) +
      (Number(this.#SYN) << 1) +
      (Number(this.#FIN) << 0)

    buffer.writeUInt8(flags, offset)
    offset++
    buffer.writeUint16BE(this.#window, offset)
    offset += 2

    const checksumOffset = offset
    buffer.writeUint16BE(0, offset)
    offset += 2
    buffer.writeUint16BE(this.#urgentPointer, offset)
    offset += 2

    if (this.#options.length > 0) {
      this.#options.copy(buffer, offset, 0, this.#options.length)
      offset += optionsLength
    }

    this.#data.copy(buffer, offset, 0, this.#data.length)
    this.#checksum = this.#calculateTCPChecksum(buffer) || this.#checksum
    buffer.writeUInt16BE(this.#checksum, checksumOffset)
    return buffer
  }

  /**
   * @return {Buffer}
   */
  get data() {
    return this.#data
  }

  set sourceIP(v) {
    this.#sourceIP = new IPV4Address(v)
  }

  set destinationIP(v) {
    this.#destinationIP = new IPV4Address(v)
  }

  /**
   * @return {IP4Address|null}
   */
  get sourceIP() {
    if (!this.#sourceIP) {
      return null
    }
    return new IPV4Address(this.#sourceIP)
  }

  /**
   * @return {IP4Address|null}
   */
  get destinationIP() {
    if (!this.#destinationIP) {
      return null
    }
    return new IPV4Address(this.#destinationIP)
  }

  get URG() {
    return this.#URG
  }

  get ACK() {
    return this.#ACK
  }

  get PSH() {
    return this.#PSH
  }

  get RST() {
    return this.#RST
  }

  get SYN() {
    return this.#SYN
  }

  /**
   * @return {boolean}
   */
  get FIN() {
    return this.#FIN
  }

  /**
   * @return {number}
   */
  get window() {
    return this.#window
  }

  get sequenceNumber() {
    return this.#sequenceNumber
  }

  get acknowledgmentNumber() {
    return this.#acknowledgmentNumber
  }

  get destinationPort() {
    return this.#destinationPort
  }

  get sourcePort() {
    return this.#sourcePort
  }
}

module.exports = TCPMessage
