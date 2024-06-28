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
    this.log = this.#logInternal.bind(this, this.#log, 1)
    this.error = this.#logInternal.bind(this, this.#error, 1)
    this.warn = this.#logInternal.bind(this, this.#warn, 2)
    this.info = this.#logInternal.bind(this, this.#info, 3)
    this.debug = this.#logInternal.bind(this, this.#debug, 4)
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
}

module.exports = Logger
