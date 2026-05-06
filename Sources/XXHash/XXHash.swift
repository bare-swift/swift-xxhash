// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Copyright (c) 2026 The bare-swift Project Authors.

/// Sendable, Foundation-free xxHash (XXH32, XXH64, XXH3-64, XXH3-128).
public enum XXHash: Sendable {
    /// XXH32 one-shot. 32-bit non-cryptographic hash; legacy. Wire-compatible
    /// with the C reference (`xxhsum -H32`) and the LZ4 frame format.
    public static func xxh32(_ bytes: some Sequence<UInt8>, seed: UInt32 = 0) -> UInt32 {
        if let result = bytes.withContiguousStorageIfAvailable({ buf -> UInt32 in
            buf.baseAddress.map { _xxh32($0, buf.count, seed) } ?? (seed &+ p32_5)
        }) {
            return result
        }
        let array = Array(bytes)
        return array.withUnsafeBufferPointer { buf in
            buf.baseAddress.map { _xxh32($0, buf.count, seed) } ?? (seed &+ p32_5)
        }
    }

    /// XXH64 one-shot. 64-bit non-cryptographic hash; legacy. Wire-compatible
    /// with the C reference (`xxhsum -H64`) and zstd content checksums.
    public static func xxh64(_ bytes: some Sequence<UInt8>, seed: UInt64 = 0) -> UInt64 {
        if let result = bytes.withContiguousStorageIfAvailable({ buf -> UInt64 in
            buf.baseAddress.map { _xxh64($0, buf.count, seed) } ?? (seed &+ p64_5)
        }) {
            return result
        }
        let array = Array(bytes)
        return array.withUnsafeBufferPointer { buf in
            buf.baseAddress.map { _xxh64($0, buf.count, seed) } ?? (seed &+ p64_5)
        }
    }

    /// XXH3-64 one-shot. 64-bit modern xxHash; substantially faster than XXH64.
    /// Wire-compatible with the C reference (`xxhsum -H3`).
    public static func xxh3_64(_ bytes: some Sequence<UInt8>, seed: UInt64 = 0) -> UInt64 {
        let secret = _xxh3_customSecret(seed: seed)
        if let result = bytes.withContiguousStorageIfAvailable({ buf -> UInt64 in
            if let p = buf.baseAddress {
                return _xxh3_64bits_internal(p, buf.count, seed, secret)
            }
            return _xxh64_avalanche(seed ^ _readLE64Secret(xxh3DefaultSecret, 56) ^ _readLE64Secret(xxh3DefaultSecret, 64))
        }) {
            return result
        }
        let array = Array(bytes)
        return array.withUnsafeBufferPointer { buf in
            if let p = buf.baseAddress {
                return _xxh3_64bits_internal(p, buf.count, seed, secret)
            }
            return _xxh64_avalanche(seed ^ _readLE64Secret(xxh3DefaultSecret, 56) ^ _readLE64Secret(xxh3DefaultSecret, 64))
        }
    }

    /// XXH3-128 one-shot. 128-bit modern xxHash. Wire-compatible with the C
    /// reference (`xxhsum -H128`).
    public static func xxh3_128(_ bytes: some Sequence<UInt8>, seed: UInt64 = 0) -> Hash128 {
        let secret = _xxh3_customSecret(seed: seed)
        let emptyResult: Hash128 = {
            let bitflipl = _readLE64Secret(xxh3DefaultSecret, 64) ^ _readLE64Secret(xxh3DefaultSecret, 72)
            let bitfliph = _readLE64Secret(xxh3DefaultSecret, 80) ^ _readLE64Secret(xxh3DefaultSecret, 88)
            return Hash128(high: _xxh64_avalanche(seed ^ bitfliph), low: _xxh64_avalanche(seed ^ bitflipl))
        }()
        if let result = bytes.withContiguousStorageIfAvailable({ buf -> Hash128 in
            if let p = buf.baseAddress {
                return _xxh3_128bits_internal(p, buf.count, seed, secret)
            }
            return emptyResult
        }) {
            return result
        }
        let array = Array(bytes)
        return array.withUnsafeBufferPointer { buf in
            if let p = buf.baseAddress {
                return _xxh3_128bits_internal(p, buf.count, seed, secret)
            }
            return emptyResult
        }
    }
}
