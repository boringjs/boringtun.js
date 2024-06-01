const UDP = 'UDP'
const TCP = 'TCP'

module.exports = {
  UDP,
  TCP,
  PROTOCOLS: /** @type{{'6':string,TCP:number, UDP:number, '17': string }}*/ {
    6: TCP,
    [TCP]: 6,
    17: UDP,
    [UDP]: 17,
  },
}
