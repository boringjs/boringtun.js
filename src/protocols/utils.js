/**
 * @param {number} numIp
 * @return {string}
 */
function ipv4Num2Str(numIp) {
  if (typeof numIp !== 'number') {
    throw TypeError('number expected')
  }

  const a = (numIp >> 24) & 0xff
  const b = (numIp >> 16) & 0xff
  const c = (numIp >> 8) & 0xff
  const d = numIp & 0xff

  return `${a}.${b}.${c}.${d}`
}

/**
 * @param {string} ipv4
 * @return {number}
 */
function ipv4Str2Num(ipv4) {
  if (typeof ipv4 !== 'string') {
    throw new TypeError('string expected')
  }

  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ipv4)) {
    throw new TypeError('invalid ipv4 format')
  }

  return ipv4.split('.').reduce((a, v) => {
    a = a * 256
    a += parseInt(v, 10)
    return a
  }, 0)
}

module.exports = {
  ipv4Num2Str,
  ipv4Str2Num
}