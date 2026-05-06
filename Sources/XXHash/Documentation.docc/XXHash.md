# ``XXHash``

Sendable, Foundation-free xxHash (XXH32, XXH64, XXH3-64, XXH3-128) for Swift 6.

## Overview

`XXHash` is a non-cryptographic hash family. Use it for checksums, content
addressing, hash-table keying, and any case where you'd otherwise reach for
CRC, MurmurHash, or FNV — but want substantially better speed and
distribution.

Four algorithms, all available as both one-shot functions and streaming
``XXHash/Digest32``-style value types:

- **XXH32** — 32-bit, legacy. Used by the LZ4 frame format.
- **XXH64** — 64-bit, legacy. Used by zstd content checksums.
- **XXH3-64** — modern recommendation. Substantially faster than XXH64; same 64-bit output.
- **XXH3-128** — 128-bit variant of XXH3. Same speed as XXH3-64 in practice.

Every algorithm accepts a seed. Wire format is identical to the upstream C
reference (`xxhsum`) and to the `twox-hash` Rust crate.

```swift
import XXHash

let h: UInt64 = XXHash.xxh3_64("hello, world".utf8)

var d = XXHash.Digest3_64()
d.update("hello, ".utf8)
d.update("world".utf8)
assert(d.finalize() == h)
```

## Topics

### One-shot

- ``XXHash/xxh32(_:seed:)``
- ``XXHash/xxh64(_:seed:)``
- ``XXHash/xxh3_64(_:seed:)``
- ``XXHash/xxh3_128(_:seed:)``

### Streaming

- ``XXHash/Digest32``
- ``XXHash/Digest64``
- ``XXHash/Digest3_64``
- ``XXHash/Digest3_128``

### 128-bit result

- ``XXHash/Hash128``
