# BoringTunJS

A userspace WireGuard VPN implementation for NodeJS based on [BoringTun](https://github.com/cloudflare/boringtun) which is written in Rust.

## Project Status: Early Development Phase

This project is at the beginning of its journey. As such, it is currently in its initial development phase, where features are being developed and the architecture is being established.

Bindings for the [BoringTun](https://github.com/cloudflare/boringtun) library are ready, but it does not include a network stack. The original library doesn't include it. It wil be written on Nodejs.

## Installation

```shell
npm install boringtunjs
```

## In progress

1. Tests
2. Network stack (tcp/udp)

## Supported platforms

1. MacOS M-chip
2. MacOS Intel-chip
3. Ubuntu 20.04 x64
4. Windows x64

## Acknowledgments

This project makes use of "BoringTun", a userspace WireGuard VPN implementation, developed and maintained by Cloudflare, Inc. We extend our gratitude to Cloudflare, Inc. and the contributors to the BoringTun project for their work. BoringTun is distributed under the BSD 3-Clause License, and we adhere to its licensing conditions in the use of this library within our project.

## Building

You need Rust installed on your machine. The build process is divided into two steps: building the static library in Rust and creating the Node.js bindings in C++.

```shell
git clone --recursive git@github.com:boringjs/boringtun.js.git 
cd boringtun.js
npm install
npm run build:boringtun
npm run build
```

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).
