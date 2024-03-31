#!/bin/bash

cd boringtun && cargo build --lib --release --no-default-features --features "ffi-bindings"
