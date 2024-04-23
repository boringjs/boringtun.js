const {ipv4Num2Str, ipv4Str2Num} = require('../src/protocols/utils.js')

describe("Utils functions", () => {
  test("Ipv4 convert string to number", () => {
    expect(ipv4Str2Num("13.251.12.118")).toBe(234556534)
    expect(ipv4Str2Num("255.255.255.254")).toBe(4294967294)
    expect(ipv4Str2Num("255.255.255.255")).toBe(4294967295)
    expect(ipv4Str2Num("0.0.0.0")).toBe(0)
  })

  test("convert number to string", () => {
    expect(ipv4Num2Str(234556534)).toBe("13.251.12.118")
    expect(ipv4Num2Str(4294967294)).toBe("255.255.255.254")
    expect(ipv4Num2Str(4294967295)).toBe("255.255.255.255")
    expect(ipv4Num2Str(0)).toBe("0.0.0.0")
  })
})

describe("UDP protocol tests", () => {
  test.skip("Create empty udp protocol", () => {})
})