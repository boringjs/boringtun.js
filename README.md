[![Wallaby.js](https://img.shields.io/badge/wallaby.js-powered-blue.svg?style=for-the-badge&logo=github)](https://wallabyjs.com/oss/)

# BoringTunJS

A userspace WireGuard VPN implementation for Node.js, written in **pure JavaScript** — no native bindings, no Rust, no C++.

## ⚠️ Research project — not for production

This is an experimental, educational implementation of the WireGuard protocol. Use it to learn, prototype, or research — **do not run it in production**.

If you need WireGuard for real workloads, use one of:

- The official [wireguard-tools](https://www.wireguard.com/install/) with a kernel or userspace driver
- A native Node.js wrapper around `wg` / `wg-quick`
- [BoringTun](https://github.com/cloudflare/boringtun) directly (Cloudflare's Rust implementation)

Expect lower throughput than any of those — this is plain JS running crypto in a single thread.

## Motivation

The goal of this project is **study and research**:

- Experiment with implementing IP-layer protocols in JavaScript — the IPv4 parser, a TCP state machine with handshake/teardown, UDP flows, and a DNS proxy — all on top of raw bytes.
- Understand the WireGuard protocol end-to-end by implementing it: the Noise_IKpsk2 handshake, session keys, replay window, rekey/keepalive timers.
- As a bonus along the way, write the underlying cryptographic primitives from their specs rather than calling a library — BLAKE2s (RFC 7693), ChaCha20-Poly1305 (RFC 7539), Poly1305 big-integer arithmetic. These were not the target of the project, but are a useful side-effect.
- Have a hackable reference: small enough to read in an afternoon, all in one language, no build toolchain.

If you are learning how IP stacks, VPNs, or the Noise protocol framework actually work, this codebase is meant to be read. If you need to ship WireGuard in production, use one of the options above.

## What changed

This project started as N-API bindings to Cloudflare's [BoringTun](https://github.com/cloudflare/boringtun) (Rust) plus a C++ wrapper. It has since been rewritten as a **pure JavaScript** implementation — including BLAKE2s, ChaCha20-Poly1305, Poly1305, and the full Noise_IKpsk2 handshake state machine. The only runtime dependency on Node.js internals is `crypto` for X25519 key generation and Diffie-Hellman (which OpenSSL provides).

The Noise protocol design and overall architecture are ported from BoringTun. We gratefully acknowledge Cloudflare's work — see the [Acknowledgments](#acknowledgments) section.

## Install

```shell
npm install boringtunjs
```

No compilation step. No postinstall. Just JavaScript.

## Requirements

- Node.js 22+ (for X25519 support in the built-in `crypto` module)

## Quick start

```js
const { Wireguard } = require('boringtunjs')

const wg = new Wireguard({
  privateKey: '3RLqvLwIYch6efW7iK7lywzFnZQfSzblDTvRwJ7CAbA=',
  listenPort: 51820,
  address: '10.8.0.1',
})

wg.addPeer({
  publicKey: '3g5U/6myr9DZf/HkNuwSKR+h1lcOJQbnAQfjrZ4q5xg=',
  allowedIPs: '10.8.0.2/32',
  keepAlive: 25,
  endpoint: '1.2.3.4:51820',
})

wg.listen()
```

## API

### Key management

```js
const { WireguardTunnel } = require('boringtunjs')

// Generate a new key pair
const { privateKey, publicKey } = WireguardTunnel.generateKeyPair()

// Or just a private key
const privateKey = WireguardTunnel.generatePrivateKey()

// Derive public from private
const publicKey = WireguardTunnel.getPublicKeyFrom(privateKey)

// Validate a base64 key
WireguardTunnel.checkValidKey(privateKey) // => true/false
```

These are also exported as top-level functions for convenience:

```js
const { generateKeyPair, generatePrivateKey, getPublicKeyFrom, checkValidKey } = require('boringtunjs')
```

### `Wireguard`

The high-level interface. Binds a UDP socket, routes IP packets to peers, and manages the local network stack (TCP/UDP).

```js
const wg = new Wireguard({
  privateKey,        // base64 X25519 private key
  listenPort,        // UDP port to bind
  address,           // interface address (e.g. '10.8.0.1')
  logLevel,          // optional, 0–4
  logger,            // optional Logger instance
})

wg.addPeer({
  publicKey,         // peer's base64 public key
  allowedIPs,        // 'CIDR,CIDR,...' — which traffic belongs to this peer
  keepAlive,         // persistent keepalive seconds (optional)
  endpoint,          // 'ip:port' (optional — can be learned from first handshake)
  name,              // optional display name
})

wg.removePeer(publicKey)   // returns boolean
wg.getPeerByKey(publicKey) // => Peer
wg.getPeers()              // => array of endpoint strings

wg.listen()                // start UDP server, IP layer, and initiate handshakes
wg.close()                 // graceful shutdown: peers, IP layer, UDP socket

wg.getStat()               // => { publicKey, listenPort, address, peers, connections }
```

`getStat()` returns:

```js
{
  publicKey: string,
  listenPort: number,
  address: string,
  peers: [{
    publicKey, name, endpoint,
    txBytes, rxBytes,
    lastHandshakeRtt,   // ms from last completed handshake
    lastHandshake,      // epoch ms of last session establishment
  }],
  connections: {
    tcp: { activeConnections: number },
    udp: { activeClients: number },
  },
}
```

### `WireguardTunnel`

The low-level Noise protocol engine. You rarely need it directly — `Wireguard` uses it internally — but it is exposed for testing and custom transports.

```js
const tunnel = new WireguardTunnel({
  privateKey, publicKey, preSharedKey, keepAlive, index,
})

tunnel.write(ipPacket)    // encapsulate IP → WireGuard UDP packet
tunnel.read(udpPacket)    // decapsulate WireGuard UDP → IP packet
tunnel.tick()             // drive timers (rekey, keepalive) — call every ~100ms
tunnel.forceHandshake()   // initiate handshake
tunnel.getStats()         // => { txBytes, rxBytes, lastHandshakeRtt, lastHandshake }
```

All methods return `{ type, data }` where `type` is one of:

- `WireguardTunnel.WIREGUARD_DONE`
- `WireguardTunnel.WRITE_TO_NETWORK`
- `WireguardTunnel.WRITE_TO_TUNNEL_IPV4`
- `WireguardTunnel.WRITE_TO_TUNNEL_IPV6`
- `WireguardTunnel.WIREGUARD_ERROR`

### Logging

Pass a log level (or a custom `Logger`) to `Wireguard` — handshake, session, and tunnel traces all flow through the same instance:

```js
const { Wireguard } = require('boringtunjs')

const wg = new Wireguard({
  privateKey,
  listenPort: 51820,
  address: '10.8.0.1',
  logLevel: 'debug', // 0 | 1/'error' | 2/'warn' | 3/'info' | 4/'debug'
})
```

Levels are evaluated once at construction: suppressed methods become no-ops and the message thunks are never invoked, so disabled logs cost nothing. For full control, construct a `Logger` yourself:

```js
const { Wireguard, Logger } = require('boringtunjs')

const logger = new Logger({
  logLevel: 'debug',
  debug: (msg) => myTransport.write('debug', msg),
  warn: (msg) => myTransport.write('warn', msg),
  callback: ({ level, log }) => metrics.record(level, log),
})

const wg = new Wireguard({ privateKey, listenPort: 51820, address: '10.8.0.1', logger })
```

## Limitations

- **Only TCP and UDP traffic exits the tunnel.** The built-in IP layer intercepts and forwards TCP streams and UDP datagrams to the host. Any other IP protocol (ICMP, SCTP, GRE, etc.) is not handled and will be silently dropped.
- **IPv4 only.** IPv6 packets are recognized at the WireGuard layer but not routed through the IP stack.
- **Single-threaded crypto.** All ChaCha20-Poly1305, Poly1305, and BLAKE2s operations run in the main JS event loop. Throughput is limited accordingly.
- **No kernel TUN integration.** This is a fully userspace implementation; it does not create a system-level interface.
- **Rate-limiting is not enforced.** Cookie replies are parsed but not generated — this library is intended as a client, not a DoS-resistant server.

## Development

```shell
git clone git@github.com:boringjs/boringtun.js.git
cd boringtun.js
npm install
npm test
npm run lint
```

Test layout:

- `tests/crypto.spec.js` — RFC 7539 / RFC 7693 test vectors for ChaCha20-Poly1305 and BLAKE2s
- `tests/tunnel.spec.js` — end-to-end handshake and data packet tests
- `tests/net-protocols.spec.js` — TCP/UDP/DNS stack tests

## Acknowledgments

This project is heavily inspired by [BoringTun](https://github.com/cloudflare/boringtun), Cloudflare's userspace WireGuard implementation in Rust. The Noise_IKpsk2 state machine, timer constants, session ring buffer, and replay-window design are all ported from BoringTun. We thank Cloudflare and the BoringTun contributors for publishing such a clean reference implementation.

BoringTun is distributed under the BSD 3-Clause License; this project follows the same license.

The port from Rust/C++ to pure JavaScript — including the Noise protocol state machine, BLAKE2s, ChaCha20-Poly1305 with Poly1305 big-integer arithmetic, and the session/timer orchestration — was carried out with significant help from [Claude Code](https://claude.com/claude-code). Thanks to Anthropic.

## License

[BSD 3-Clause License](https://opensource.org/licenses/BSD-3-Clause).
