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

extension XXHash {
    /// Streaming XXH32 digest. Buffers up to 16 bytes of pending input; flushes
    /// a stripe when full; replays the unconsumed tail at finalize time.
    public struct Digest32: Sendable {
        @usableFromInline var v1: UInt32
        @usableFromInline var v2: UInt32
        @usableFromInline var v3: UInt32
        @usableFromInline var v4: UInt32
        @usableFromInline let seed: UInt32
        @usableFromInline var totalLen: UInt64 = 0
        @usableFromInline var buffer: [UInt8] = []

        public init(seed: UInt32 = 0) {
            self.seed = seed
            self.v1 = seed &+ XXHash.p32_1 &+ XXHash.p32_2
            self.v2 = seed &+ XXHash.p32_2
            self.v3 = seed
            self.v4 = seed &- XXHash.p32_1
            self.buffer.reserveCapacity(16)
        }

        public mutating func update(_ bytes: some Sequence<UInt8>) {
            for byte in bytes {
                buffer.append(byte)
                totalLen &+= 1
            }
            while buffer.count >= 16 {
                buffer.withUnsafeBufferPointer { buf in
                    let p = buf.baseAddress!
                    v1 = XXHash._xxh32_round(v1, XXHash._readLE32(p, 0))
                    v2 = XXHash._xxh32_round(v2, XXHash._readLE32(p, 4))
                    v3 = XXHash._xxh32_round(v3, XXHash._readLE32(p, 8))
                    v4 = XXHash._xxh32_round(v4, XXHash._readLE32(p, 12))
                }
                buffer.removeFirst(16)
            }
        }

        public func finalize() -> UInt32 {
            var hash: UInt32
            if totalLen >= 16 {
                hash = ((v1 << 1)  | (v1 >> 31))
                     &+ ((v2 << 7)  | (v2 >> 25))
                     &+ ((v3 << 12) | (v3 >> 20))
                     &+ ((v4 << 18) | (v4 >> 14))
            } else {
                hash = seed &+ XXHash.p32_5
            }
            hash = hash &+ UInt32(truncatingIfNeeded: totalLen)
            return buffer.withUnsafeBufferPointer { buf -> UInt32 in
                let p = buf.baseAddress!
                let n = buf.count
                var i = 0
                var h = hash
                while i + 4 <= n {
                    h = h &+ XXHash._readLE32(p, i) &* XXHash.p32_3
                    h = ((h << 17) | (h >> 15)) &* XXHash.p32_4
                    i += 4
                }
                while i < n {
                    h = h &+ UInt32(p[i]) &* XXHash.p32_5
                    h = ((h << 11) | (h >> 21)) &* XXHash.p32_1
                    i += 1
                }
                return XXHash._xxh32_avalanche(h)
            }
        }
    }
}
