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
cargo add sha-256
```

## Usage
The general idea is "bytes in, bytes out". This is the most efficient input and output type to minimise conversions. Consequently, if you want the hash as a hex string you will need to convert it from bytes to hex afterwards - but don't worry, there's a function in this library for exactly that!

```rs
fn main() {
    let mut sha256: sha256 = sha256::new();
    // Message can be [u8] or Vec<u8>
    let message: String = "hello".to_string();
    println!("Message: {}", message);
    let messageBytes: &[u8] = message.as_bytes();
    let hash: [u8; 32] = sha256.digest(messageBytes);
    // convert the hash to a hex string
    let hash_hex = sha256::u8a_to_hex(&hash);
    println!("Hash: {}", hash_hex);
}
```
See the examples dir for a full project example.

## Benchmark
How fast is this library? Up to **25%** faster than the [`sha256`](https://crates.io/crates/sha256) and [`sha`](https://crates.io/crates/sha), and they contain use of Intel's `SHA-NI` cpu instructions (via a feature flag).

**However**, the above figures were obtained through some rough benchmarks on only my hardware. More thorough benchmarks are required, YMMV!

// TODO further benchmarks
