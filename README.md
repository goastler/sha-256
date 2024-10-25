# Sha_256

A fast implementation of sha-256 in rust.

## Features
- [x] Partially unrolled loops for increased efficiency from cpu cache usage
- [x] Bypass rust safety checks to eliminate array index safety checks
- [x] Only use stack memory to avoid `malloc` calls
- [x] Minimised memory footprint via array reuse across multiple stages of sha256
- [x] No memory reallocation, so subsequent calls to sha256 reuse memory
- [x] Optimised memory layout for increased cpu cache hits
- [x] No needless byte array conversion (e.g. u8a to u32a)
- [x] Pure rust, no fancy embedded assembly language or specific cpu instructions
- [x] No dependencies
- [x] No std requirements

## Installation

In your project, run:
```bash
cargo add sha_256
```

## Usage

Import the library
```rust
use sha_256::Sha256;
```

Create an instance of the sha256 struct.

```rust
let mut sha256: Sha256 = Sha256::new();
```

Create your message in bytes.
```rust
let bytes = &[0u8, 1u8, 2u8];
```

Run sha256 to create a digest/hash.
```rust
let hash: [u8; 32] = sha256.digest(bytes);
```

The general idea is "bytes in, bytes out". This is the most efficient input and output type to minimise conversions.

You will need to convert your input into bytes, e.g. string to bytes. See [example project](/example/).

If you want the hash as a hex string you will need to convert it from bytes to hex afterwards. See [example project](/example/).

## Benchmark
How fast is this library? Up to **25%** faster than the [`sha256`](https://crates.io/crates/sha256) and [`sha`](https://crates.io/crates/sha), and they contain use of Intel's `SHA-NI` cpu instructions (via a feature flag).

**However**, the above figures were obtained through some rough benchmarks on only my hardware. More thorough benchmarks are required, YMMV!

// TODO further benchmarks

## Links
- [crates.io](https://crates.io/crates/sha_256)
