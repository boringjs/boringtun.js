class Logger {
  #logLevel = 0
  #log = console.log
  #warn = console.warn
  #info = console.info
  #debug = console.debug
  #error = console.error
  #callback = null

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
   * @param {function} [options.callback] Fires only for enabled levels; suppressed levels are no-ops, by design, so the callback mirrors console output.
   */
  constructor({ logLevel = 0, log, warn, debug, info, error, callback = null } = {}) {
    this.callback = callback
    this.#logLevel = Logger.#logLevelMap[logLevel?.toString().toLowerCase()] ?? 0
    this.#log = log || this.#log
    this.#warn = warn || this.#warn
    this.#debug = debug || this.#debug
    this.#error = error || this.#error
    this.#info = info || this.#info
    this.isLog = 1 <= this.#logLevel
    this.isError = 1 <= this.#logLevel
    this.isWarn = 2 <= this.#logLevel
    this.isInfo = 3 <= this.#logLevel
    this.isDebug = 4 <= this.#logLevel
    this.log = this.isLog ? this.#logInternal.bind(this, 'log', this.#log) : () => {}
    this.error = this.isError ? this.#logInternal.bind(this, 'error', this.#error) : () => {}
    this.warn = this.isWarn ? this.#logInternal.bind(this, 'warn', this.#warn) : () => {}
    this.info = this.isInfo ? this.#logInternal.bind(this, 'info', this.#info) : () => {}
    this.debug = this.isDebug ? this.#logInternal.bind(this, 'debug', this.#debug) : () => {}
    this.ignore = () => {}
  }

  /**
   * @param {function} v
   */
  set callback(v) {
    if (typeof v !== 'function' && v !== null) {
      throw new TypeError('Logger callback must be a function')
    }
    this.#callback = v
  }

  /**
   * Dispatches a log call. If the first arg is a thunk, it's invoked lazily
   * (no work when the level is disabled, since the whole method is a no-op).
   * A thunk may return an array — spread as multiple args to the sink — or a
   * single value, passed as-is.
   */
  #logInternal(level, logFn, logCallback, ...args) {
    if (typeof logCallback === 'function') {
      const log = logCallback()

      this.#callback?.({ level, log })

      return Array.isArray(log) ? logFn(...log) : logFn(log)
    }

    this.#callback?.({ level, log: [logCallback, ...args].join(',') })
    return logFn(logCallback, ...args)
  }
}

module.exports = Logger
