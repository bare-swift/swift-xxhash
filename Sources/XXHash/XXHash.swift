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
}
