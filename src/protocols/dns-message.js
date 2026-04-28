/*
 https://www.rfc-editor.org/rfc/rfc1035
 4.1.1. Header section format

 The header contains the following fields:
                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      ID                       |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    QDCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ANCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    NSCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ARCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 4.1.2. Question section format
                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                                               |
 /                     QNAME                     /
 /                                               /
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     QTYPE                     |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     QCLASS                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 4.1.3. Resource record format
                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                                               |
 /                                               /
 /                      NAME                     /
 |                                               |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      TYPE                     |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     CLASS                     |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      TTL                      |
 |                                               |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                   RDLENGTH                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 /                     RDATA                     /
 /                                               /
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

class DNSMessage {
  #id = 0
  #qr = 0
  #data = Buffer.alloc(0)
  #valid = true

  constructor(input) {
    if (!(input instanceof Buffer) || input.length < 12) {
      this.#valid = false
      return
      // throw new TypeError('Input is not buffer')
      // todo: create empty message
    }
    this.#data = input

    this.#qr = (this.#data[2] & 0b10000000) >> 7
    this.#id = this.#data.readUInt16BE(0)
  }

  get valid() {
    return this.#valid
  }

  /**
   * @return {number}
   */
  get id() {
    return this.#id
  }

  set id(v) {
    if (Number.isNaN(v) || v < 0) {
      throw new TypeError('Not valid input')
    }

    this.#id = v
    this.#data.writeUInt16BE(this.#id)
  }

  get data() {
    return this.#data
  }

  parseMessage() {
    if (!this.#valid) {
      return null
    }

    const buffer = this.#data

    const header = {
      id: this.#id,
      qr: (buffer[2] & 0b10000000) >> 7,
      opcode: (buffer[2] & 0b01111000) >> 3,
      aa: (buffer[2] & 0b00000100) >> 2,
      tc: (buffer[2] & 0b00000010) >> 1,
      rd: buffer[2] & 0b00000001,
      ra: (buffer[3] & 0b10000000) >> 7,
      z: (buffer[3] & 0b01110000) >> 4,
      rcode: buffer[3] & 0b00001111,
      qdcount: buffer.readUInt16BE(4),
      ancount: buffer.readUInt16BE(6),
      nscount: buffer.readUInt16BE(8),
      arcount: buffer.readUInt16BE(10),
    }

    let offset = 12

    const decodeName = (buf, startOffset) => {
      const visited = new Set()

      const readLabels = (off) => {
        if (visited.has(off)) {
          return { labels: [], endOffset: off }
        }
        visited.add(off)

        const labels = []
        let localOffset = off
        // Iterate labels until zero-length or pointer
        while (true) {
          const len = buf[localOffset]
          if (len === 0) {
            localOffset += 1
            break
          }
          // Check for compression pointer 11xx xxxx
          if ((len & 0b11000000) === 0b11000000) {
            const pointer = ((len & 0b00111111) << 8) | buf[localOffset + 1]
            // Jump and read labels from pointer target
            const { labels: restLabels } = readLabels(pointer)
            labels.push(...restLabels)
            // For a pointer, the name ends and encoded size is exactly 2 bytes
            localOffset += 2
            break
          }

          const label = buf.slice(localOffset + 1, localOffset + 1 + len).toString('ascii')
          labels.push(label)
          localOffset += 1 + len
        }

        return { labels, endOffset: localOffset }
      }

      const { labels, endOffset } = readLabels(startOffset)
      return { name: labels.join('.'), nextOffset: endOffset }
    }

    const questions = []
    for (let i = 0; i < header.qdcount; i++) {
      const { name, nextOffset } = decodeName(buffer, offset)
      offset = nextOffset
      const qtype = buffer.readUInt16BE(offset)
      offset += 2
      const qclass = buffer.readUInt16BE(offset)
      offset += 2
      questions.push({ name, type: qtype, class: qclass })
    }

    const parseRData = (type, rdataOffset, rdlength) => {
      if (type === 1 && rdlength === 4) {
        // A record
        const a = buffer[rdataOffset]
        const b = buffer[rdataOffset + 1]
        const c = buffer[rdataOffset + 2]
        const d = buffer[rdataOffset + 3]
        return `${a}.${b}.${c}.${d}`
      }

      // Domain name based rdata types (CNAME=5, NS=2, PTR=12, MX=15 (after pref))
      if (type === 5 || type === 2 || type === 12) {
        const { name } = decodeName(buffer, rdataOffset)
        return name
      }

      if (type === 15) {
        // MX: preference (2 bytes) + exchange
        const preference = buffer.readUInt16BE(rdataOffset)
        const { name } = decodeName(buffer, rdataOffset + 2)
        return { preference, exchange: name }
      }

      // Return raw buffer slice by default
      return buffer.slice(rdataOffset, rdataOffset + rdlength)
    }

    const parseRecords = (count) => {
      const records = []
      for (let i = 0; i < count; i++) {
        const nameDecoded = decodeName(buffer, offset)
        const name = nameDecoded.name
        offset = nameDecoded.nextOffset

        const type = buffer.readUInt16BE(offset)
        offset += 2
        const rclass = buffer.readUInt16BE(offset)
        offset += 2
        const ttl = buffer.readUInt32BE(offset)
        offset += 4
        const rdlength = buffer.readUInt16BE(offset)
        offset += 2

        const rdataOffset = offset
        const data = parseRData(type, rdataOffset, rdlength)
        // move offset by rdlength regardless of how we decoded (compression may jump)
        offset += rdlength

        records.push({ name, type, class: rclass, ttl, data })
      }
      return records
    }

    const answers = parseRecords(header.ancount)
    const authorities = parseRecords(header.nscount)
    const additionals = parseRecords(header.arcount)

    return {
      id: header.id,
      header,
      questions,
      answers,
      authorities,
      additionals,
    }
  }

  isResponse() {
    return this.#qr === 1
  }

  isRequest() {
    return this.#qr === 0
  }
}

module.exports = DNSMessage
