const { UDP, TCP, PROTOCOLS } = require('./constants.js')
const IPV4Address = require('./ip4-address.js')
const UDPMessage = require('./udp-message.js')
const TCPMessage = require('./tcp-message.js')

class IP4Packet {
  #version = 4
  #headerLength = 20
  #typeOfService = 0
  #totalLength = 0
  #identification = 0
  #flags = 0
  #fragmentOffset = 0
  #timeToLive = 64
  #protocol = 0
  #protocolName = 0
  #headerChecksum = 0
  #sourceIP = new IPV4Address(0)
  #destinationIP = new IPV4Address(0)
  #payload = Buffer.alloc(0)
  #options = Buffer.alloc(0)
  #modified = false

  /**
   * @param {?Buffer} buffer
   */
  constructor(input) {
    if (input instanceof Buffer) {
      this.#parse(input)
      return
    }

    if (!input) {
      // empty packet
      return
    }

    if (typeof input !== 'object') {
      throw new TypeError('Invalid IPPackage type')
    }

    if (Reflect.has(input, 'ipFlags')) {
      this.#flags = input.ipFlags
    }

    if (Reflect.has(input, 'ipFragmentOffset')) {
      this.#fragmentOffset = input.ipFragmentOffset
    }

    if (input.sourceIP) {
      this.sourceIP = new IPV4Address(input.sourceIP)
    }

    if (input.destinationIP) {
      this.destinationIP = new IPV4Address(input.destinationIP)
    }

    if (input.ttl) {
      this.#timeToLive = input.ttl
    }

    if (input.identification) {
      this.#identification = input.identification
    }

    if (input.protocol === UDP) {
      this.#protocolName = UDP
      this.#protocol = PROTOCOLS.UDP
      const udp = new UDPMessage({
        sourceIP: this.#sourceIP,
        destinationIP: this.#destinationIP,
        sourcePort: input.sourcePort,
        destinationPort: input.destinationPort,
        udpData: input.udpData,
      })

      this.#payload = udp.toBuffer()
      return
    }

    if (input.protocol === TCP) {
      this.#protocolName = TCP
      this.#protocol = PROTOCOLS.TCP

      const tcpMessage = new TCPMessage({
        sourceIP: input.sourceIP,
        destinationIP: input.destinationIP,
        sourcePort: input.sourcePort,
        destinationPort: input.destinationPort,
        sequenceNumber: input.sequenceNumber,
        acknowledgmentNumber: input.acknowledgmentNumber,
        urgentPointer: input.urgentPointer,
        options: input.options,
        data: input.data,
        URG: input.URG,
        ACK: input.ACK,
        PSH: input.PSH,
        RST: input.RST,
        SYN: input.SYN,
        FIN: input.FIN,
        window: input.window,
      })

      this.#payload = tcpMessage.toBuffer()
    }
  }


  debugView() {
    return {
      version: this.#version,
      headerLength: this.#headerLength,
      totalLength: this.#totalLength,
      ttl: this.#timeToLive,
      protocol: this.#protocolName,
      sourceIp: this.#sourceIP.toString(),
      destinationIP: this.#destinationIP.toString(),
      payloadLength: this.#payload.length,
      // payload: this.#payload.toString('base64'),
      // payloadBuffer: this.#payload,
    }
  }

  /**
   * @return {IP4Address}
   */
  get sourceIP() {
    return this.#sourceIP
  }

  /**
   * @param {Buffer|string|number} v
   */
  set destinationIP(v) {
    this.#modified = true
    this.#destinationIP = new IPV4Address(v)
  }

  /**
   * @return {IP4Address}
   */
  get destinationIP() {
    return this.#destinationIP
  }

  /**
   * @param {Buffer|string|number} v
   */
  set sourceIP(v) {
    this.#modified = true
    this.#sourceIP = new IPV4Address(v)
  }

  get protocol() {
    return this.#protocolName
  }

  get protocolNum() {
    return this.#protocol
  }

  get rawProtocol() {
    return this.#protocol
  }

  /**
   * @param {Buffer} buffer
   */
  #parse(buffer) {
    let offset = 0
    const firstByte = buffer.readUInt8(offset++)
    this.#version = firstByte >> 4
    this.#headerLength = (firstByte & 0b1111) << 2 // Header Length is in 32-bit words
    this.#typeOfService = buffer.readUInt8(offset++)
    this.#totalLength = buffer.readUInt16BE(offset)
    offset += 2

    this.#identification = buffer.readUInt16BE(offset)
    offset += 2

    this.#flags = buffer.readUInt8(offset) >> 5
    this.#fragmentOffset = buffer.readUInt16BE(offset) & 0b1111111111111
    offset += 2

    this.#timeToLive = buffer.readUInt8(offset++)

    this.#protocol = buffer.readUInt8(offset++)

    this.#protocolName = PROTOCOLS[this.#protocol]

    this.#headerChecksum = buffer.readUInt16BE(offset)
    offset += 2

    this.#sourceIP = new IPV4Address(buffer, offset)
    offset += 4

    this.#destinationIP = new IPV4Address(buffer, offset)
    offset += 4

    if (this.#headerLength > 20) {
      this.#options = Buffer.from(this.#headerLength - 20)
      buffer.copy(this.#options, 0, offset, this.#headerLength)
      offset += this.#options.length
    }

    const payloadLength = this.#totalLength - this.#headerLength
    if (payloadLength > 0) {
      this.#payload = Buffer.alloc(payloadLength)
      buffer.copy(this.#payload, 0, offset, this.#totalLength)
    }
  }

  /**
   * @param {Buffer} rawData
   * @returns {IP4Packet}
   * @throws
   */
  static parseFrom(rawData) {
    if (rawData instanceof Buffer) {
      return new IP4Packet(rawData)
    }

    throw new TypeError('Invalid init data')
  }

  #calculateChecksum(buffer) {
    let sum = 0

    for (let i = 0; i < buffer.length; i += 2) {
      if (i + 1 < buffer.length) {
        sum += buffer.readUInt16BE(i)
      } else {
        // If the data length is odd, pad with a zero byte for checksum calculation
        sum += buffer.readUInt8(i) << 8
      }
    }

    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16)
    }

    sum = ~sum & 0xffff
    return sum === 0 ? 0xffff : sum
  }

  /**
   * @returns {Buffer}
   */
  toBuffer() {
    let offset = 0
    this.#totalLength = 2 + 2 + 2 + 1 + 1 + 2 + 4 + 4 + this.#options.length + this.#payload.length + 2
    const buffer = Buffer.alloc(this.#totalLength)

    buffer.writeUInt8((this.#version << 4) + (this.#headerLength >> 2), offset++)

    buffer.writeUInt8(this.#typeOfService, offset++)
    buffer.writeUInt16BE(this.#totalLength, offset)
    offset += 2

    buffer.writeUInt16BE(this.#identification, offset)
    offset += 2

    buffer.writeUInt16BE((this.#flags << 13) + this.#fragmentOffset, offset)
    offset += 2

    buffer.writeUInt8(this.#timeToLive, offset++)

    buffer.writeUInt8(this.#protocol, offset++)

    const checksumOffset = offset

    buffer.writeUInt16BE(0, offset) // offset === 10 checksum
    offset += 2

    this.#sourceIP.toBuffer().copy(buffer, offset, 0)
    offset += 4

    this.#destinationIP.toBuffer().copy(buffer, offset, 0)
    offset += 4

    if (this.#options.length > 0) {
      this.#options.copy(buffer, offset, 0, this.#options.length)
      offset += this.#options.length
    }

    const checksum = this.#calculateChecksum(buffer, offset)
    buffer.writeUInt16BE(checksum, checksumOffset)

    this.#payload.copy(buffer, offset, 0, this.#payload.length)

    return buffer
  }

  get payload() {
    return this.#payload // todo copy
  }

  getUDPMessage() {
    if (this.#protocolName !== 'UDP') {
      return null
    }

    const udp = new UDPMessage(this.#payload)

    udp.destinationIP = this.#destinationIP
    udp.sourceIP = this.#sourceIP

    return udp
  }

  getTCPMessage() {
    if (this.#protocolName !== 'TCP') {
      return null
    }

    const tcp = new TCPMessage(this.#payload)

    tcp.destinationIP = this.#destinationIP
    tcp.sourceIP = this.#sourceIP

    return tcp
  }
}

module.exports = IP4Packet
