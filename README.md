# swift-xxhash

Sendable, Foundation-free xxHash (XXH32, XXH64, XXH3-64, XXH3-128) for Swift 6.

Wire-compatible with the [xxHash C reference](https://github.com/Cyan4973/xxHash) (`xxhsum`) and the [`twox-hash`](https://crates.io/crates/twox-hash) Rust crate.

Part of the [bare-swift](https://github.com/bare-swift) ecosystem.

## Install

Add to your `Package.swift`:

```swift
.package(url: "https://github.com/bare-swift/swift-xxhash.git", from: "0.1.0")
```

Then depend on the `XXHash` product:

```swift
.product(name: "XXHash", package: "swift-xxhash")
```

## Usage

```swift
import XXHash

// One-shot
let h32: UInt32 = XXHash.xxh32("abc".utf8)                   // 0x32D153FF
let h64: UInt64 = XXHash.xxh64("abc".utf8)                   // 0x44BC2CF5AD770999
let h3_64: UInt64 = XXHash.xxh3_64("abc".utf8)
let h3_128 = XXHash.xxh3_128("abc".utf8)                     // XXHash.Hash128

// With seed
let seeded = XXHash.xxh64("abc".utf8, seed: 0xCAFE)

// Streaming
var d = XXHash.Digest3_64()
d.update("hello, ".utf8)
d.update("world".utf8)
let result: UInt64 = d.finalize()                            // == XXHash.xxh3_64("hello, world".utf8)

// 128-bit hash → bytes (big-endian) or hex string
print(h3_128.description)        // 32 lowercase hex chars
print(h3_128.bytes)              // [UInt8] (16 bytes)
```

## Documentation

Full DocC documentation: <https://bare-swift.github.io/swift-xxhash/>

## Source

Translated from the [`twox-hash`](https://crates.io/crates/twox-hash) Rust crate and the [Cyan4973/xxHash](https://github.com/Cyan4973/xxHash) C reference.

## License

Apache 2.0 with LLVM exception. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
