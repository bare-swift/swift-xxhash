// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Copyright (c) 2026 The bare-swift Project Authors.

extension XXHash {
    // MARK: - XXH32 constants (from the xxHash specification)

    @usableFromInline static let p32_1: UInt32 = 0x9E3779B1
    @usableFromInline static let p32_2: UInt32 = 0x85EBCA77
    @usableFromInline static let p32_3: UInt32 = 0xC2B2AE3D
    @usableFromInline static let p32_4: UInt32 = 0x27D4EB2F
    @usableFromInline static let p32_5: UInt32 = 0x165667B1

    @inlinable
    static func _xxh32_round(_ acc: UInt32, _ lane: UInt32) -> UInt32 {
        var a = acc &+ (lane &* p32_2)
        a = (a << 13) | (a >> 19)
        return a &* p32_1
    }

    @inlinable
    static func _xxh32_avalanche(_ h: UInt32) -> UInt32 {
        var h = h
        h ^= h >> 15
        h = h &* p32_2
        h ^= h >> 13
        h = h &* p32_3
        h ^= h >> 16
        return h
    }

    @inlinable
    static func _readLE32(_ buf: UnsafePointer<UInt8>, _ i: Int) -> UInt32 {
        return UInt32(buf[i])
            | (UInt32(buf[i+1]) << 8)
            | (UInt32(buf[i+2]) << 16)
            | (UInt32(buf[i+3]) << 24)
    }

    static func _xxh32(_ buf: UnsafePointer<UInt8>, _ length: Int, _ seed: UInt32) -> UInt32 {
        var hash: UInt32
        var i = 0
        if length >= 16 {
            var v1 = seed &+ p32_1 &+ p32_2
            var v2 = seed &+ p32_2
            var v3 = seed
            var v4 = seed &- p32_1
            let limit = length - 16
            while i <= limit {
                v1 = _xxh32_round(v1, _readLE32(buf, i));      i += 4
                v2 = _xxh32_round(v2, _readLE32(buf, i));      i += 4
                v3 = _xxh32_round(v3, _readLE32(buf, i));      i += 4
                v4 = _xxh32_round(v4, _readLE32(buf, i));      i += 4
            }
            hash = ((v1 << 1)  | (v1 >> 31))
                 &+ ((v2 << 7)  | (v2 >> 25))
                 &+ ((v3 << 12) | (v3 >> 20))
                 &+ ((v4 << 18) | (v4 >> 14))
        } else {
            hash = seed &+ p32_5
        }
        hash = hash &+ UInt32(length)
        while i + 4 <= length {
            hash = hash &+ _readLE32(buf, i) &* p32_3
            hash = ((hash << 17) | (hash >> 15)) &* p32_4
            i += 4
        }
        while i < length {
            hash = hash &+ UInt32(buf[i]) &* p32_5
            hash = ((hash << 11) | (hash >> 21)) &* p32_1
            i += 1
        }
        return _xxh32_avalanche(hash)
    }
}
