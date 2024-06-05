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

    this.#qr = (input[2] & 0b10000000) >> 7
    this.#id = input.readUInt16BE(0)
    this.#data = input
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
  }

  get data() {
    return this.#data
  }

  isResponse() {
    return this.#qr === 1
  }

  isRequest() {
    return this.#qr === 0
  }
}

module.exports = DNSMessage
