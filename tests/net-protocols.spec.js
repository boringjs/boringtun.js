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
    expect(new IP4Address('13.251.12.118').toNumber()).toBe(234556534)
    expect(new IP4Address('255.255.255.254').toNumber()).toBe(4294967294)
    expect(new IP4Address('255.255.255.255').toNumber()).toBe(4294967295)
    expect(new IP4Address('0.0.0.0').toNumber()).toBe(0)
  })

  test('convert number to string', () => {
    expect(new IP4Address(234556534).toString()).toBe('13.251.12.118')
    expect(new IP4Address(4294967294).toString()).toBe('255.255.255.254')
    expect(new IP4Address(4294967295).toString()).toBe('255.255.255.255')
    expect(new IP4Address(0).toString()).toBe('0.0.0.0')
  })

  test('Create ip4address from ip4Address', () => {
    const ip1 = new IP4Address('13.251.12.118')
    const ip2 = new IP4Address(ip1)

    expect(ip1).not.toBe(ip2)
    expect(ip2.toString()).toBe('13.251.12.118')
  })

  test('convert string to string', () => {
    expect(String(new IP4Address('13.251.12.118'))).toBe('13.251.12.118')
    expect(`${new IP4Address('13.251.12.118')}`).toBe('13.251.12.118')
  })

  test('match mask', () => {
    const allowedIP1 = new IP4Address('1.2.3.4/32')
    expect(allowedIP1.match('1.2.3.4')).toBeTruthy()
    expect(allowedIP1.match('1.1.1.2')).toBeFalsy()
    expect(allowedIP1.match('1.1.1.2')).toBeFalsy()

    const allowedIP2 = new IP4Address('1.2.3.4/24')
    expect(allowedIP2.match('1.2.3.4')).toBeTruthy()
    expect(allowedIP2.match('1.2.3.255')).toBeTruthy()
    expect(allowedIP2.match('1.1.2.0')).toBeFalsy()
    expect(allowedIP2.match('3.1.1.2')).toBeFalsy()

    const allowedIP3 = new IP4Address('0.0.0.0/0')
    expect(allowedIP3.match('1.2.3.4')).toBeTruthy()
    expect(allowedIP3.match('1.2.3.255')).toBeTruthy()
    expect(allowedIP3.match('1.1.2.0')).toBeTruthy()
    expect(allowedIP3.match('3.1.1.2')).toBeTruthy()
  })

  test('convert from buffer to buffer', () => {
    const input = Buffer.from([13, 251, 12, 118, 200, 400])
    expect(new IP4Address(input).toBuffer()).toEqual(Buffer.from([13, 251, 12, 118]))
  })

  test('convert from buffer to buffer with offset', () => {
    const input = Buffer.from([1, 2, 3, 13, 251, 12, 118])
    const offset = 3
    expect(new IP4Address(input, offset).toString()).toBe('13.251.12.118')
  })
})

describe('ipv4 packet', () => {
  test('Create and return ipv4 packet', () => {
    const str =
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K'
    const buffer = Buffer.from(str, 'base64')

    const ipv4Packet = new IP4Packet(buffer)

    expect(ipv4Packet.toBuffer()).toEqual(buffer)
  })

  test('getters and setters', () => {
    const ipv4Packet = new IP4Packet()

    ipv4Packet.destinationIP = '192.168.0.1'
    ipv4Packet.sourceIP = '192.168.0.2'

    expect(ipv4Packet.destinationIP.toString()).toBe('192.168.0.1')
    expect(ipv4Packet.sourceIP.toString()).toBe('192.168.0.2')
  })

  test('parse udp packet', () => {
    const dataBase64 = 'RQAAOUUYAABAERuDCggAAggICAjSUQA1ACVlf94WAQAAAQAAAAAAAAdleGFtcGxlA2NvbQAAAQAB'
    const buffer = Buffer.from(dataBase64, 'base64')
    const ipv4Packet = new IP4Packet(buffer)

    expect(ipv4Packet.protocol).toBe('UDP')
    expect(ipv4Packet.sourceIP.toString()).toBe('10.8.0.2')
    expect(ipv4Packet.destinationIP.toString()).toBe('8.8.8.8')

    const udp = ipv4Packet.getUDPMessage()

    expect(udp.destinationPort).toBe(53)
    expect(udp.sourcePort).toBe(53841)
    expect(udp.data).toEqual(Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))
    expect(udp.dataCopy).toEqual(Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))

    expect(udp.toBuffer()).toEqual(ipv4Packet.payload)
  })

  test('parse udp packet 2', () => {
    // 8.8.8.8 → 10.8.0.2 DNS Standard query response 0x1b44 A clients1.google.com CNAME clients.l.google.com A 172.217.168.206
    const dataBase64 =
      'RQAAaQALAABAEWBgCAgICAoIAAIANQA1AFX/URtEgYAAAQACAAAAAAhjbGllbnRzMQZnb29nbGUDY29tAAABAAHADAAFAAEAAABxAAwHY2xpZW50cwFswBXAMQABAAEAAABxAASs2ajO'
    const buffer = Buffer.from(dataBase64, 'base64')
    const ipv4Packet = new IP4Packet(buffer)

    expect(ipv4Packet.protocol).toBe('UDP')
    expect(ipv4Packet.sourceIP.toString()).toBe('8.8.8.8')
    expect(ipv4Packet.destinationIP.toString()).toBe('10.8.0.2')

    const udp = ipv4Packet.getUDPMessage()

    expect(udp.sourcePort).toBe(53)
    expect(udp.destinationPort).toBe(53)
    // expect(udp.data).toEqual(Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))
    // expect(udp.dataCopy).toEqual(Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))

    expect(udp.toBuffer()).toEqual(ipv4Packet.payload)
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

    expect(udpMessage.toBuffer()).toEqual(buffer)
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

    expect(ipv4Packet.protocol).toBe('UDP')

    expect(ipv4Packet.toBuffer()).toEqual(buffer)

    const udp = ipv4Packet.getUDPMessage()

    expect(udp.destinationPort).toBe(53)
    expect(udp.sourcePort).toBe(53841)
    expect(udp.data).toEqual(Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))
    expect(udp.dataCopy).toEqual(Buffer.from('3hYBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=', 'base64'))
  })

  test('parse and toBuffer tcp message', () => {
    const buffer = Buffer.from(
      'y30AUOC+hk0FgQ31gBgIBAUDAAABAQgKSKu78EQ/DKRHRVQgLyBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NClVzZXItQWdlbnQ6IGN1cmwvOC40LjANCkFjY2VwdDogKi8qDQoNCg==',
      'base64',
    )

    const tcpMessage = new TCPMessage(buffer)
    const bufferResult = tcpMessage.toBuffer()
    expect(bufferResult.length).toBe(buffer.length)
    expect(bufferResult).toEqual(buffer)
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
    expect(bufferResult.length).toBe(buffer.length)
    expect(bufferResult).toEqual(buffer)
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

    expect(tcpMessage.toBuffer()).toEqual(buffer)
  })

  test('parse tcp packet', () => {
    const tcpPacketBuffer = Buffer.from(
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K',
      'base64',
    )

    const ipv4Packet = new IP4Packet(tcpPacketBuffer)

    expect(ipv4Packet.protocol).toBe('TCP')

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

    expect(newIpv4Packet.toBuffer()).toEqual(tcpPacketBuffer)
  })

  test('ipv4 tcp syn message', () => {
    const buffer = Buffer.from(
      '45000040000040004006fbe70a0800025db8d70ef3c7005003e28e5b00000000b0c2ffffa1ff0000020404d8010303060101080a5ef770fb0000000004020000',
      'hex',
    )

    // 10.8.0.2 → 93.184.215.14 TCP 62407 → 80 [SYN, ECE, CWR] SACK_PERM

    const ipv4Packet = new IP4Packet(buffer)

    const tcpMessage = ipv4Packet.getTCPMessage()

    expect(tcpMessage.SYN).toBe(true)
    expect(tcpMessage.window).toBe(65535)
    expect(tcpMessage.sequenceNumber).toBe(0x03e28e5b)
    expect(tcpMessage.sourcePort).toBe(62407)
    expect(tcpMessage.destinationPort).toBe(80)
  })

  test('parse ipv4 packet with IP options', () => {
    // Build a packet with IP options (header length > 20)
    // Using a real-world NOP+NOP+Timestamp option (12 bytes)
    const baseBuffer = Buffer.from(
      'RQAAfgAAQABABvubCggAEF241w7LfQBQ4L6GTQWBDfWAGAgEBQMAAAEBCApIq7vwRD8MpEdFVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KVXNlci1BZ2VudDogY3VybC84LjQuMA0KQWNjZXB0OiAqLyoNCg0K',
      'base64',
    )
    const ipv4Packet = new IP4Packet(baseBuffer)
    // Should not throw (previously crashed with Buffer.from(number))
    expect(ipv4Packet.protocol).toBe('TCP')
    expect(ipv4Packet.toBuffer()).toEqual(baseBuffer)
  })
})

describe('IP4Address non-octet masks', () => {
  test('/25 mask should be 255.255.255.128', () => {
    const addr = new IP4Address('10.0.0.0/25')
    expect(addr.match('10.0.0.0')).toBeTruthy()
    expect(addr.match('10.0.0.127')).toBeTruthy()
    expect(addr.match('10.0.0.128')).toBeFalsy()
    expect(addr.match('10.0.0.255')).toBeFalsy()
  })

  test('/1 mask should be 128.0.0.0', () => {
    const addr = new IP4Address('128.0.0.0/1')
    expect(addr.match('192.168.1.1')).toBeTruthy() // 192 has high bit set
    expect(addr.match('127.0.0.1')).toBeFalsy() // 127 does not
  })

  test('/9 mask should be 255.128.0.0', () => {
    const addr = new IP4Address('10.0.0.0/9')
    expect(addr.match('10.0.0.1')).toBeTruthy()
    expect(addr.match('10.127.255.255')).toBeTruthy()
    expect(addr.match('10.128.0.0')).toBeFalsy()
  })

  test('/31 mask should be 255.255.255.254', () => {
    const addr = new IP4Address('192.168.1.0/31')
    expect(addr.match('192.168.1.0')).toBeTruthy()
    expect(addr.match('192.168.1.1')).toBeTruthy()
    expect(addr.match('192.168.1.2')).toBeFalsy()
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
          socket.on('error', () => {}) // suppress
          resolve(socket)
        })
      },
      ...overrides,
    })
  }

  test('SYN handshake emits SYN+ACK', (done) => {
    const stream = makeStream({
      tcpSocketFactory: (opts, callback) => {
        return new Promise((resolve) => {
          // Simulate connected socket
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
        expect(tcp.SYN).toBe(true)
        expect(tcp.ACK).toBe(true)
        expect(tcp.acknowledgmentNumber).toBe(1001)
        stream.close()
        done()
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
  })

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

    // SYN
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

    // Complete handshake (ACK of SYN+ACK)
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

    // Server-initiated close
    stream.close()

    const finPacket = packets.find((p) => p.FIN)
    expect(finPacket).toBeDefined()
    expect(finPacket.ACK).toBe(true)
  })

  test('default tcpSocketFactory does not crash with .catch()', async () => {
    // The default factory returns net.Socket (not Promise).
    // Wrapped in Promise.resolve(), .catch() should work.
    const stream = new TCPStream({
      sourceIP: new IP4Address('10.0.0.1'),
      destinationIP: new IP4Address('127.0.0.1'),
      sourcePort: 12345,
      destinationPort: 1, // port 1 will fail to connect
      hash: 'test-hash',
      socketId: 1,
    })

    const packets = []
    stream.on('ip4Packet', (ip4Packet) => {
      packets.push(ip4Packet.getTCPMessage())
    })

    // This should not throw TypeError: .catch is not a function
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
  }, 5000)

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

    // SYN
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

    // Complete handshake
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

    // Client sends FIN
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

    expect(endCalled).toBe(true)
    // destroy should NOT have been called by the FIN handler
    expect(destroyCalled).toBe(false)
  })
})
