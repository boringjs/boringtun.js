const DNSMessage = require('../src/protocols/dns-message.js')

describe('DNSMessage.parseMessage', () => {
  test('parse simple DNS query example.com A', () => {
    // From existing UDP test payload in net-protocols.spec.js
    const udpData = Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64')
    const dns = new DNSMessage(udpData)
    expect(dns.valid).toBe(true)
    expect(dns.isRequest()).toBe(true)

    const parsed = dns.parseMessage()

    expect(parsed.id).toBe(0xDE16) // 0xDE16 from first two bytes of udpData
    expect(parsed.header.qdcount).toBe(1)
    expect(parsed.header.ancount).toBe(0)
    expect(parsed.questions.length).toBe(1)
    expect(parsed.questions[0]).toEqual({ name: 'example.com', type: 1, class: 1 })
  })

  test('parse simple dns query response', () => {
    const ipBuffer = Buffer.from('AACBgAABAAEAAAABA3d3dwZiZXQzNjUDY29tAAABAAHADAABAAEAACYeAAQF4rMKAAApAgAAAAAAAZkADAGVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64')

    const dns = new DNSMessage(ipBuffer)

    console.log('dns', dns.parseMessage())

  })

  test('parse DNS response with CNAME and A', () => {
    // From existing test "parse udp packet 2" payload (ancount=2)
    const ipBuffer = Buffer.from(
      'RQAAaQALAABAEWBgCAgICAoIAAIANQA1AFX/URtEgYAAAQACAAAAAAhjbGllbnRzMQZnb29nbGUDY29tAAABAAHADAAFAAEAAABxAAwHY2xpZW50cwFswBXAMQABAAEAAABxAASs2ajO',
      'base64',
    )

    // Extract DNS portion via IP4Packet -> UDPMessage
    const IP4Packet = require('../src/protocols/ip4-packet.js')
    const ipv4Packet = new IP4Packet(ipBuffer)
    const udp = ipv4Packet.getUDPMessage()
    const dns = new DNSMessage(udp.data)
    expect(dns.valid).toBe(true)
    expect(dns.isResponse()).toBe(true)

    const parsed = dns.parseMessage()

    expect(parsed.header.ancount).toBeGreaterThanOrEqual(1)
    expect(parsed.questions.length).toBe(1)
    // Question should be clients1.google.com
    expect(parsed.questions[0].name).toBe('clients1.google.com')

    // Expect at least one answer; allow either CNAME or A first depending on order
    const names = new Set(parsed.answers.map((a) => a.name))
    expect(names.has('clients1.google.com')).toBe(true)

    // Find CNAME if present
    const cname = parsed.answers.find((a) => a.type === 5)
    if (cname) {
      expect(typeof cname.data).toBe('string')
      expect(cname.data.includes('google.com')).toBe(true)
    }

    // Find A record if present
    const arec = parsed.answers.find((a) => a.type === 1)
    if (arec) {
      expect(arec.data).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
    }
  })
})


