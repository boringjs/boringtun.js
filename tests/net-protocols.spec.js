const { describe, test } = require('node:test')
const assert = require('node:assert/strict')
const IP4Address = require('../src/protocols/ip4-address.js')
const IP4Packet = require('../src/protocols/ip4-packet.js')
const UDPMessage = require('../src/protocols/udp-message.js')
const TCPMessage = require('../src/protocols/tcp-message.js')
const TCPStream = require('../src/protocols/tcp-stream.js')
const { TCP } = require('../src/protocols/constants.js')

const net = require('net')
const delay = (time = 0) => new Promise((resolve) => setTimeout(resolve, time))

describe('IP4Address', () => {
  test('Ipv4 convert string to number', () => {
    assert.equal(new IP4Address('13.251.12.118').toNumber(), 234556534)
    assert.equal(new IP4Address('255.255.255.254').toNumber(), 4294967294)
    assert.equal(new IP4Address('255.255.255.255').toNumber(), 4294967295)
    assert.equal(new IP4Address('0.0.0.0').toNumber(), 0)
  })

  test('convert number to string', () => {
    assert.equal(new IP4Address(234556534).toString(), '13.251.12.118')
    assert.equal(new IP4Address(4294967294).toString(), '255.255.255.254')
    assert.equal(new IP4Address(4294967295).toString(), '255.255.255.255')
    assert.equal(new IP4Address(0).toString(), '0.0.0.0')
  })

  test('Create ip4address from ip4Address', () => {
    const ip1 = new IP4Address('13.251.12.118')
    const ip2 = new IP4Address(ip1)

    assert.notEqual(ip1, ip2)
    assert.equal(ip2.toString(), '13.251.12.118')
  })

  test('convert string to string', () => {
    assert.equal(String(new IP4Address('13.251.12.118')), '13.251.12.118')
    assert.equal(`${new IP4Address('13.251.12.118')}`, '13.251.12.118')
  })

  test('match mask', () => {
    const allowedIP1 = new IP4Address('1.2.3.4/32')
    assert.ok(allowedIP1.match('1.2.3.4'))
    assert.ok(!allowedIP1.match('1.1.1.2'))
    assert.ok(!allowedIP1.match('1.1.1.2'))

    const allowedIP2 = new IP4Address('1.2.3.4/24')
    assert.ok(allowedIP2.match('1.2.3.4'))
    assert.ok(allowedIP2.match('1.2.3.255'))
    assert.ok(!allowedIP2.match('1.1.2.0'))
    assert.ok(!allowedIP2.match('3.1.1.2'))

    const allowedIP3 = new IP4Address('0.0.0.0/0')
    assert.ok(allowedIP3.match('1.2.3.4'))
    assert.ok(allowedIP3.match('1.2.3.255'))
    assert.ok(allowedIP3.match('1.1.2.0'))
    assert.ok(allowedIP3.match('3.1.1.2'))
  })

  test('convert from buffer to buffer', () => {
    const input = Buffer.from([13, 251, 12, 118, 200, 400])
    assert.deepEqual(new IP4Address(input).toBuffer(), Buffer.from([13, 251, 12, 118]))
  })

  test('convert from buffer to buffer with offset', () => {
    const input = Buffer.from([1, 2, 3, 13, 251, 12, 118])
    const offset = 3
    assert.equal(new IP4Address(input, offset).toString(), '13.251.12.118')
  })
})

describe('ipv4 packet', () => {
  test('Create and return ipv4 packet', () => {
    const str =
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K'
    const buffer = Buffer.from(str, 'base64')

    const ipv4Packet = new IP4Packet(buffer)

    assert.deepEqual(ipv4Packet.toBuffer(), buffer)
  })

  test('getters and setters', () => {
    const ipv4Packet = new IP4Packet()

    ipv4Packet.destinationIP = '192.168.0.1'
    ipv4Packet.sourceIP = '192.168.0.2'

    assert.equal(ipv4Packet.destinationIP.toString(), '192.168.0.1')
    assert.equal(ipv4Packet.sourceIP.toString(), '192.168.0.2')
  })

  test('parse udp packet', () => {
    const dataBase64 = 'RQAAOUUYAABAERuDCggAAggICAjSUQA1ACVlf94WAQAAAQAAAAAAAAdleGFtcGxlA2NvbQAAAQAB'
    const buffer = Buffer.from(dataBase64, 'base64')
    const ipv4Packet = new IP4Packet(buffer)

    assert.equal(ipv4Packet.protocol, 'UDP')
    assert.equal(ipv4Packet.sourceIP.toString(), '10.8.0.2')
    assert.equal(ipv4Packet.destinationIP.toString(), '8.8.8.8')

    const udp = ipv4Packet.getUDPMessage()

    assert.equal(udp.destinationPort, 53)
    assert.equal(udp.sourcePort, 53841)
    assert.deepEqual(udp.data, Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))
    assert.deepEqual(udp.dataCopy, Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))

    assert.deepEqual(udp.toBuffer(), ipv4Packet.payload)
  })

  test('parse udp packet 2', () => {
    const dataBase64 =
      'RQAAaQALAABAEWBgCAgICAoIAAIANQA1AFX/URtEgYAAAQACAAAAAAhjbGllbnRzMQZnb29nbGUDY29tAAABAAHADAAFAAEAAABxAAwHY2xpZW50cwFswBXAMQABAAEAAABxAASs2ajO'
    const buffer = Buffer.from(dataBase64, 'base64')
    const ipv4Packet = new IP4Packet(buffer)

    assert.equal(ipv4Packet.protocol, 'UDP')
    assert.equal(ipv4Packet.sourceIP.toString(), '8.8.8.8')
    assert.equal(ipv4Packet.destinationIP.toString(), '10.8.0.2')

    const udp = ipv4Packet.getUDPMessage()

    assert.equal(udp.sourcePort, 53)
    assert.equal(udp.destinationPort, 53)

    assert.deepEqual(udp.toBuffer(), ipv4Packet.payload)
  })

  test('create udp message', () => {
    const udpData = Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64')
    const udpMessage = new UDPMessage({
      sourceIP: new IP4Address('10.8.0.2'),
      destinationIP: new IP4Address('8.8.8.8'),
      sourcePort: 53841,
      destinationPort: 53,
      udpData,
    })

    const buffer = Buffer.from('0lEANQAlZX/eFgEAAAEAAAAAAAAHZXhhbXBsZQNjb20AAAEAAQ==', 'base64')

    assert.deepEqual(udpMessage.toBuffer(), buffer)
  })

  test('create udp ip4 packet', () => {
    const udpData = Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64')
    const ipv4Packet = new IP4Packet({
      protocol: 'UDP',
      sourceIP: '10.8.0.2',
      destinationIP: '8.8.8.8',
      sourcePort: 53841,
      destinationPort: 53,
      ttl: 64,
      identification: 17688,
      udpData,
    })

    const dataBase64 = 'RQAAOUUYAABAERuDCggAAggICAjSUQA1ACVlf94WAQAAAQAAAAAAAAdleGFtcGxlA2NvbQAAAQAB'
    const buffer = Buffer.from(dataBase64, 'base64')

    assert.equal(ipv4Packet.protocol, 'UDP')

    assert.deepEqual(ipv4Packet.toBuffer(), buffer)

    const udp = ipv4Packet.getUDPMessage()

    assert.equal(udp.destinationPort, 53)
    assert.equal(udp.sourcePort, 53841)
    assert.deepEqual(udp.data, Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))
    assert.deepEqual(udp.dataCopy, Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))
  })

  test('parse and toBuffer tcp message', () => {
    const buffer = Buffer.from(
      'y30AUOC+hk0FgQ31gBgIBAUDAAABAQgKSKu78EQ/DKRHRVQgLyBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NClVzZXItQWdlbnQ6IGN1cmwvOC40LjANCkFjY2VwdDogKi8qDQoNCg==',
      'base64',
    )

    const tcpMessage = new TCPMessage(buffer)
    const bufferResult = tcpMessage.toBuffer()
    assert.equal(bufferResult.length, buffer.length)
    assert.deepEqual(bufferResult, buffer)
  })

  test('parse and toBuffer tcp message and checksum', () => {
    const buffer = Buffer.from(
      'y30AUOC+hk0FgQ31gBgIBAUDAAABAQgKSKu78EQ/DKRHRVQgLyBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NClVzZXItQWdlbnQ6IGN1cmwvOC40LjANCkFjY2VwdDogKi8qDQoNCg==',
      'base64',
    )

    const tcpMessage = new TCPMessage(buffer)

    tcpMessage.destinationIP = '93.184.215.14'
    tcpMessage.sourceIP = '10.8.0.16'

    const bufferResult = tcpMessage.toBuffer()
    assert.equal(bufferResult.length, buffer.length)
    assert.deepEqual(bufferResult, buffer)
  })

  test('Create new tcp message', () => {
    const buffer = Buffer.from(
      'y30AUOC+hk0FgQ31gBgIBAUDAAABAQgKSKu78EQ/DKRHRVQgLyBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NClVzZXItQWdlbnQ6IGN1cmwvOC40LjANCkFjY2VwdDogKi8qDQoNCg==',
      'base64',
    )

    const tcpMessage = new TCPMessage({
      sourceIP: '10.8.0.16',
      destinationIP: '93.184.215.14',
      sourcePort: 52093,
      destinationPort: 80,
      sequenceNumber: 3770582605,
      acknowledgmentNumber: 92343797,
      urgentPointer: 0,
      options: Buffer.from([1, 1, 8, 10, 72, 171, 187, 240, 68, 63, 12, 164]),
      data: 'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n',
      URG: false,
      ACK: true,
      PSH: true,
      RST: false,
      SYN: false,
      FIN: false,
      window: 2052,
    })

    assert.deepEqual(tcpMessage.toBuffer(), buffer)
  })

  test('parse tcp packet', () => {
    const tcpPacketBuffer = Buffer.from(
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K',
      'base64',
    )

    const ipv4Packet = new IP4Packet(tcpPacketBuffer)

    assert.equal(ipv4Packet.protocol, 'TCP')

    const newIpv4Packet = new IP4Packet({
      protocol: TCP,
      ipFlags: 2,
      ttl: 64,
      sourceIP: '10.8.0.16',
      destinationIP: '93.184.215.14',
      sourcePort: 52093,
      destinationPort: 80,
      sequenceNumber: 3770582605,
      acknowledgmentNumber: 92343797,
      urgentPointer: 0,
      options: Buffer.from([1, 1, 8, 10, 72, 171, 187, 240, 68, 63, 12, 164]),
      data: 'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n',
      URG: false,
      ACK: true,
      PSH: true,
      RST: false,
      SYN: false,
      FIN: false,
      window: 2052,
    })

    assert.deepEqual(newIpv4Packet.toBuffer(), tcpPacketBuffer)
  })

  test('ipv4 tcp syn message', () => {
    const buffer = Buffer.from(
      '45000040000040004006fbe70a0800025db8d70ef3c7005003e28e5b00000000b0c2ffffa1ff0000020404d8010303060101080a5ef770fb0000000004020000',
      'hex',
    )

    const ipv4Packet = new IP4Packet(buffer)

    const tcpMessage = ipv4Packet.getTCPMessage()

    assert.equal(tcpMessage.SYN, true)
    assert.equal(tcpMessage.window, 65535)
    assert.equal(tcpMessage.sequenceNumber, 0x03e28e5b)
    assert.equal(tcpMessage.sourcePort, 62407)
    assert.equal(tcpMessage.destinationPort, 80)
  })

  test('parse ipv4 packet with IP options', () => {
    const baseBuffer = Buffer.from(
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K',
      'base64',
    )
    const ipv4Packet = new IP4Packet(baseBuffer)
    assert.equal(ipv4Packet.protocol, 'TCP')
    assert.deepEqual(ipv4Packet.toBuffer(), baseBuffer)
  })
})

describe('IP4Address non-octet masks', () => {
  test('/25 mask should be 255.255.255.128', () => {
    const addr = new IP4Address('10.0.0.0/25')
    assert.ok(addr.match('10.0.0.0'))
    assert.ok(addr.match('10.0.0.127'))
    assert.ok(!addr.match('10.0.0.128'))
    assert.ok(!addr.match('10.0.0.255'))
  })

  test('/1 mask should be 128.0.0.0', () => {
    const addr = new IP4Address('128.0.0.0/1')
    assert.ok(addr.match('192.168.1.1'))
    assert.ok(!addr.match('127.0.0.1'))
  })

  test('/9 mask should be 255.128.0.0', () => {
    const addr = new IP4Address('10.0.0.0/9')
    assert.ok(addr.match('10.0.0.1'))
    assert.ok(addr.match('10.127.255.255'))
    assert.ok(!addr.match('10.128.0.0'))
  })

  test('/31 mask should be 255.255.255.254', () => {
    const addr = new IP4Address('192.168.1.0/31')
    assert.ok(addr.match('192.168.1.0'))
    assert.ok(addr.match('192.168.1.1'))
    assert.ok(!addr.match('192.168.1.2'))
  })
})

describe('TCPStream', () => {
  const makeStream = (overrides = {}) => {
    return new TCPStream({
      sourceIP: new IP4Address('10.0.0.1'),
      destinationIP: new IP4Address('93.184.215.14'),
      sourcePort: 12345,
      destinationPort: 80,
      hash: 'test-hash',
      socketId: 1,
      tcpSocketFactory: ({ host, port }, callback) => {
        return new Promise((resolve) => {
          const socket = net.connect({ host: '127.0.0.1', port: 1 }, callback)
          socket.on('error', () => {})
          resolve(socket)
        })
      },
      ...overrides,
    })
  }

  test('SYN handshake emits SYN+ACK', () =>
    new Promise((resolve) => {
      const stream = makeStream({
        tcpSocketFactory: (opts, callback) => {
          return new Promise((resolve) => {
            const { PassThrough } = require('stream')
            const fakeSocket = new PassThrough()
            fakeSocket.destroy = () => {}
            setTimeout(callback, 0)
            resolve(fakeSocket)
          })
        },
      })

      stream.on('ip4Packet', (ip4Packet) => {
        const tcp = ip4Packet.getTCPMessage()
        if (tcp.SYN && tcp.ACK) {
          assert.equal(tcp.SYN, true)
          assert.equal(tcp.ACK, true)
          assert.equal(tcp.acknowledgmentNumber, 1001)
          stream.close()
          resolve()
        }
      })

      stream.send(
        new TCPMessage({
          sourceIP: '10.0.0.1',
          destinationIP: '93.184.215.14',
          sourcePort: 12345,
          destinationPort: 80,
          SYN: true,
          sequenceNumber: 1000,
          window: 65535,
        }),
      )
    }))

  test('server close sends FIN+ACK not bare FIN', async () => {
    const { PassThrough } = require('stream')
    const fakeSocket = new PassThrough()
    fakeSocket.destroy = () => {}

    const stream = makeStream({
      tcpSocketFactory: (opts, callback) => {
        return new Promise((resolve) => {
          setTimeout(callback, 0)
          resolve(fakeSocket)
        })
      },
    })

    const packets = []
    stream.on('ip4Packet', (ip4Packet) => {
      packets.push(ip4Packet.getTCPMessage())
    })

    stream.send(
      new TCPMessage({
        sourceIP: '10.0.0.1',
        destinationIP: '93.184.215.14',
        sourcePort: 12345,
        destinationPort: 80,
        SYN: true,
        sequenceNumber: 1000,
        window: 65535,
      }),
    )

    await delay(50)

    const synAck = packets.find((p) => p.SYN && p.ACK)
    stream.send(
      new TCPMessage({
        sourceIP: '10.0.0.1',
        destinationIP: '93.184.215.14',
        sourcePort: 12345,
        destinationPort: 80,
        ACK: true,
        sequenceNumber: 1001,
        acknowledgmentNumber: synAck.sequenceNumber + 1,
        window: 65535,
      }),
    )

    stream.close()

    const finPacket = packets.find((p) => p.FIN)
    assert.notEqual(finPacket, undefined)
    assert.equal(finPacket.ACK, true)
  })

  test('default tcpSocketFactory does not crash with .catch()', { timeout: 5000 }, async () => {
    const stream = new TCPStream({
      sourceIP: new IP4Address('10.0.0.1'),
      destinationIP: new IP4Address('127.0.0.1'),
      sourcePort: 12345,
      destinationPort: 1,
      hash: 'test-hash',
      socketId: 1,
    })

    const packets = []
    stream.on('ip4Packet', (ip4Packet) => {
      packets.push(ip4Packet.getTCPMessage())
    })

    stream.send(
      new TCPMessage({
        sourceIP: '10.0.0.1',
        destinationIP: '127.0.0.1',
        sourcePort: 12345,
        destinationPort: 1,
        SYN: true,
        sequenceNumber: 1000,
        window: 65535,
      }),
    )

    await delay(100)
    stream.close()
  })

  test('client FIN uses socket.end() not socket.destroy()', async () => {
    const { PassThrough } = require('stream')
    const fakeSocket = new PassThrough()
    let endCalled = false
    let destroyCalled = false
    fakeSocket.end = () => {
      endCalled = true
    }
    fakeSocket.destroy = () => {
      destroyCalled = true
    }

    const stream = makeStream({
      tcpSocketFactory: (opts, callback) => {
        return new Promise((resolve) => {
          setTimeout(callback, 0)
          resolve(fakeSocket)
        })
      },
    })

    const packets = []
    stream.on('ip4Packet', (ip4Packet) => {
      packets.push(ip4Packet.getTCPMessage())
    })

    stream.send(
      new TCPMessage({
        sourceIP: '10.0.0.1',
        destinationIP: '93.184.215.14',
        sourcePort: 12345,
        destinationPort: 80,
        SYN: true,
        sequenceNumber: 1000,
        window: 65535,
      }),
    )

    await delay(50)

    const synAck = packets.find((p) => p.SYN && p.ACK)
    stream.send(
      new TCPMessage({
        sourceIP: '10.0.0.1',
        destinationIP: '93.184.215.14',
        sourcePort: 12345,
        destinationPort: 80,
        ACK: true,
        sequenceNumber: 1001,
        acknowledgmentNumber: synAck.sequenceNumber + 1,
        window: 65535,
      }),
    )

    stream.send(
      new TCPMessage({
        sourceIP: '10.0.0.1',
        destinationIP: '93.184.215.14',
        sourcePort: 12345,
        destinationPort: 80,
        FIN: true,
        ACK: true,
        sequenceNumber: 1001,
        acknowledgmentNumber: synAck.sequenceNumber + 1,
        window: 65535,
      }),
    )

    assert.equal(endCalled, true)
    assert.equal(destroyCalled, false)
  })
})
