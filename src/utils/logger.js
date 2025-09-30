class Logger {
  #logLevel = 0
  #log = console.log
  #warn = console.warn
  #info = console.info
  #debug = console.debug
  #error = console.error

  static #logLevelMap = {
    undefined: 0,
    0: 0,
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    log: 1,
    error: 1,
    warn: 2,
    info: 3,
    debug: 4,
  }

  /**
   * @param {object} [options]
   * @param {number|string} [options.logLevel]
   * @param {function} [options.log]
   * @param {function} [options.warn]
   * @param {function} [options.debug]
   * @param {function} [options.info]
   * @param {function} [options.error]
   */
  constructor({ logLevel = 0, log, warn, debug, info, error } = {}) {
    this.#logLevel = Logger.#logLevelMap[logLevel?.toString().toLowerCase()] || 0
    this.#log = log || this.#log
    this.#warn = warn || this.#warn
    this.#debug = debug || this.#debug
    this.#error = error || this.#error
    this.#info = info || this.#info
    this.log = 1 <= this.#logLevel ? this.#logInternal.bind(this, this.#log) : () => {}
    this.error = 1 <= this.#logLevel ? this.#logInternal.bind(this, this.#error) : () => {}
    this.warn = 2 <= this.#logLevel ? this.#logInternal.bind(this, this.#warn) : () => {}
    this.info = 3 <= this.#logLevel ? this.#logInternal.bind(this, this.#info) : () => {}
    this.debug = 4 <= this.#logLevel ? this.#logInternal.bind(this, this.#debug) : () => {}
  }

  #logInternal(logFn, logCallback, ...args) {
    if (typeof logCallback === 'function') {
      const result = logCallback()
      return Array.isArray(result) ? logFn(...result) : logFn(result)
    }

    return logFn(logCallback, ...args)
  }
}

module.exports = Logger
