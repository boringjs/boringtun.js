class Logger {
  #logLevel = 0
  #log = console.log
  #warn = console.warn
  #info = console.info
  #debug = console.debug
  #error = console.error

  constructor({ logLevel = 0, log, warn, debug, info, error } = {}) {
    this.#logLevel = logLevel
    this.#log = log || this.#log
    this.#warn = warn || this.#warn
    this.#debug = debug || this.#debug
    this.#error = error || this.#error
    this.#info = info || this.#info
  }

  #logInternal(logFn, logFnLevel, logCallback) {
    if (logFnLevel > this.#logLevel) {
      return
    }

    if (typeof logCallback !== 'function') {
      if (Array.isArray(logCallback)) {
        return logFn(...logCallback)
      }
      return logFn(logCallback)
    }

    const result = logCallback()

    if (Array.isArray(result)) {
      return logFn(...result)
    }

    return logFn(result)
  }

  /**
   * @param {Function|string} fn
   */
  log(fn) {
    this.#logInternal(this.#error, 1, fn)
  }

  /**
   * @param {Function|string|Error} fn
   */
  error(fn) {
    this.#logInternal(this.#error, 1, fn)
  }

  /**
   * @param {Function|string} fn
   */
  warn(fn) {
    this.#logInternal(this.#error, 2, fn)
  }

  /**
   * @param {Function|string} fn
   */
  info(fn) {
    this.#logInternal(this.#error, 3, fn)
  }

  /**
   * @param {Function|string} fn
   */
  debug(fn) {
    this.#logInternal(this.#error, 4, fn)
  }
}

module.exports = Logger
