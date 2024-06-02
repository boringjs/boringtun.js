const IP4Address = require('../src/protocols/ip4-address.js')
const IP4Packet = require('../src/protocols/ip4-packet.js')
const UDPMessage = require('../src/protocols/udp-message.js')
const TCPMessage = require('../src/protocols/tcp-message.js')
const { TCP } = require('../src/protocols/constants.js')

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
})
