class Logger {
  #logLevel = 0
  #log = console.log
  #warn = console.warn
  #info = console.info
  #debug = console.debug
  #error = console.error
  #callback = null
  #includeLevel = true

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
   * @param {boolean} [options.includeLevel] When true (default) prepends `[LEVEL]` to every emitted log so output follows the `[LEVEL][LAYER][SUB] msg` convention shared across boringtunjs / boringmitm. Set to `false` if your sink already tags level externally.
   */
  constructor({ logLevel = 0, log, warn, debug, info, error, callback = null, includeLevel = true } = {}) {
    this.callback = callback
    this.#includeLevel = includeLevel !== false
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
   *
   * Thunk return shapes:
   *  - string  → `[LEVEL]${str}` (e.g. `[DEBUG][TUNNEL][PEER_1] msg`)
   *  - array   → spread as multi-arg to the sink; `[LEVEL]` prepended to first string element
   *  - object  → `f` field gets `[LEVEL]` prepended in front of the existing layer prefix
   *
   * The callback fires with the *unprefixed* `level` and the original log payload, so
   * downstream consumers see structured fields without parsing the level back out.
   */
  #logInternal(level, logFn, logCallback, ...args) {
    if (typeof logCallback === 'function') {
      const log = logCallback()

      this.#callback?.({ level, log })

      const out = this.#includeLevel ? Logger.#applyLevelTag(level, log) : log
      return Array.isArray(out) ? logFn(...out) : logFn(out)
    }

    this.#callback?.({ level, log: [logCallback, ...args].join(',') })
    if (this.#includeLevel) {
      return logFn(`[${level.toUpperCase()}]`, logCallback, ...args)
    }
    return logFn(logCallback, ...args)
  }

  static #applyLevelTag(level, log) {
    const tag = `[${level.toUpperCase()}]`
    if (typeof log === 'string') return `${tag}${log}`
    if (Array.isArray(log)) {
      if (log.length === 0) return [tag]
      return typeof log[0] === 'string' ? [`${tag}${log[0]}`, ...log.slice(1)] : [tag, ...log]
    }
    if (log && typeof log === 'object') {
      return { ...log, f: log.f ? `${tag}${log.f}` : tag }
    }
    return [tag, log]
  }
}

module.exports = Logger
