const IP4Address = require('./ip4-address.js')

class UDPClient {
  #lastUpdate = 0
  #sourceIP = new IP4Address(0)
  #sourcePort = 0

  constructor({ sourceIP, sourcePort }) {
    this.#lastUpdate = Date.now()
    this.#sourceIP = new IP4Address(sourceIP)
    this.#sourcePort = sourcePort
  }

  get lastUpdate() {
    return this.#lastUpdate
  }

  get sourceIP() {
    return this.#sourceIP
  }

  get sourcePort() {
    return this.#sourcePort
  }

  update() {
    this.#lastUpdate = Date.now()
  }
}

module.exports = UDPClient
