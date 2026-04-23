const { describe, test } = require('node:test')
const assert = require('node:assert/strict')
const DNSMessage = require('../src/protocols/dns-message.js')

describe('DNSMessage.parseMessage', { skip: true }, () => {
  test('parse simple DNS query example.com A', () => {
    const udpData = Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64')
    const dns = new DNSMessage(udpData)
    assert.equal(dns.valid, true)
    assert.equal(dns.isRequest(), true)

    const parsed = dns.parseMessage()

    assert.equal(parsed.id, 0xde16)
    assert.equal(parsed.header.qdcount, 1)
    assert.equal(parsed.header.ancount, 0)
    assert.equal(parsed.questions.length, 1)
    assert.deepEqual(parsed.questions[0], { name: 'example.com', type: 1, class: 1 })
  })

  test('parse simple dns query response', () => {
    const ipBuffer = Buffer.from(
      'AACBgAABAAEAAAABA3d3dwZiZXQzNjUDY29tAAABAAHADAABAAEAACYeAAQF4rMKAAApAgAAAAAAAZkADAGVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      'base64',
    )

    const dns = new DNSMessage(ipBuffer)

    console.log('dns', dns.parseMessage())
  })

  test('parse DNS response with CNAME and A', () => {
    const ipBuffer = Buffer.from(
      'RQAAaQALAABAEWBgCAgICAoIAAIANQA1AFX/URtEgYAAAQACAAAAAAhjbGllbnRzMQZnb29nbGUDY29tAAABAAHADAAFAAEAAABxAAwHY2xpZW50cwFswBXAMQABAAEAAABxAASs2ajO',
      'base64',
    )

    const IP4Packet = require('../src/protocols/ip4-packet.js')
    const ipv4Packet = new IP4Packet(ipBuffer)
    const udp = ipv4Packet.getUDPMessage()
    const dns = new DNSMessage(udp.data)
    assert.equal(dns.valid, true)
    assert.equal(dns.isResponse(), true)

    const parsed = dns.parseMessage()

    assert.ok(parsed.header.ancount >= 1)
    assert.equal(parsed.questions.length, 1)
    assert.equal(parsed.questions[0].name, 'clients1.google.com')

    const names = new Set(parsed.answers.map((a) => a.name))
    assert.ok(names.has('clients1.google.com'))

    const cname = parsed.answers.find((a) => a.type === 5)
    if (cname) {
      assert.equal(typeof cname.data, 'string')
      assert.ok(cname.data.includes('google.com'))
    }

    const arec = parsed.answers.find((a) => a.type === 1)
    if (arec) {
      assert.match(arec.data, /^\d+\.\d+\.\d+\.\d+$/)
    }
  })
})
