const IP4Address = require('../src/protocols/ip4-address.js')

describe("Test IP4Address class", () => {
  test("Ipv4 convert string to number", () => {
    expect(new IP4Address("13.251.12.118").toNumber()).toBe(234556534)
    expect(new IP4Address("255.255.255.254").toNumber()).toBe(4294967294)
    expect(new IP4Address("255.255.255.255").toNumber()).toBe(4294967295)
    expect(new IP4Address("0.0.0.0").toNumber()).toBe(0)
  })

  test("convert number to string", () => {
    expect(new IP4Address(234556534).toString()).toBe("13.251.12.118")
    expect(new IP4Address(4294967294).toString()).toBe("255.255.255.254")
    expect(new IP4Address(4294967295).toString()).toBe("255.255.255.255")
    expect(new IP4Address(0).toString()).toBe("0.0.0.0")
  })

  test('convert string to string', () => {
    expect(String(new IP4Address("13.251.12.118"))).toBe("13.251.12.118")
    expect(`${new IP4Address("13.251.12.118")}`).toBe("13.251.12.118")
  })

  test('convert from buffer to buffer', () => {
    const input = Buffer.from([13, 251, 12, 118, 200, 400])
    expect(new IP4Address(input).toBuffer())
      .toEqual(Buffer.from([13, 251, 12, 118]))
  })

  test('convert from buffer to buffer with offset', () => {
    const input = Buffer.from([1, 2, 3, 13, 251, 12, 118])
    const offset = 3
    expect(new IP4Address(input, offset).toString()).toBe('13.251.12.118')

  })
})

describe("UDP protocol tests", () => {
  test.skip("Create empty udp protocol", () => {
  })
})