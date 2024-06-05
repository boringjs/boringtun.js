class Deque {
  #backStack = []
  #frontStack = []

  #normalize() {
    if (this.#frontStack.length !== 0) {
      return
    }

    while (this.#backStack.length) {
      this.#frontStack.push(this.#backStack.pop())
    }
  }

  push(...values) {
    this.#backStack.push(...values)
  }

  shift() {
    this.#normalize()
    return this.#frontStack.pop()
  }

  unshift(value) {
    this.#normalize()
    this.#frontStack.push(value)
  }

  /**
   * @return {number}
   */
  get size() {
    return this.#backStack.length + this.#frontStack.length
  }

  get back() {
    if (this.#backStack.length) {
      return this.#backStack[this.#backStack.length - 1]
    }

    if (this.#frontStack.length) {
      return this.#frontStack[0]
    }

    return undefined
  }

  get front() {
    this.#normalize()
    return this.#frontStack[this.#frontStack.length - 1]
  }
}

module.exports = Deque
