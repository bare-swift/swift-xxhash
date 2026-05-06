// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Copyright (c) 2026 The bare-swift Project Authors.

extension XXHash {
    // MARK: - XXH64 constants (from the xxHash specification)

    @usableFromInline static let p64_1: UInt64 = 0x9E3779B185EBCA87
    @usableFromInline static let p64_2: UInt64 = 0xC2B2AE3D27D4EB4F
    @usableFromInline static let p64_3: UInt64 = 0x165667B19E3779F9
    @usableFromInline static let p64_4: UInt64 = 0x85EBCA77C2B2AE63
    @usableFromInline static let p64_5: UInt64 = 0x27D4EB2F165667C5

    @inlinable
    static func _xxh64_round(_ acc: UInt64, _ lane: UInt64) -> UInt64 {
        var a = acc &+ (lane &* p64_2)
        a = (a << 31) | (a >> 33)
        return a &* p64_1
    }

    @inlinable
    static func _xxh64_mergeRound(_ acc: UInt64, _ lane: UInt64) -> UInt64 {
        let l = _xxh64_round(0, lane)
        var a = acc ^ l
        a = a &* p64_1 &+ p64_4
        return a
    }

    @inlinable
    static func _xxh64_avalanche(_ h: UInt64) -> UInt64 {
        var h = h
        h ^= h >> 33
        h = h &* p64_2
        h ^= h >> 29
        h = h &* p64_3
        h ^= h >> 32
        return h
    }

    @inlinable
    static func _readLE64(_ buf: UnsafePointer<UInt8>, _ i: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<8 {
            v |= UInt64(buf[i + k]) << (8 * k)
        }
        return v
    }

    static func _xxh64(_ buf: UnsafePointer<UInt8>, _ length: Int, _ seed: UInt64) -> UInt64 {
        var hash: UInt64
        var i = 0
        if length >= 32 {
            var v1 = seed &+ p64_1 &+ p64_2
            var v2 = seed &+ p64_2
            var v3 = seed
            var v4 = seed &- p64_1
            let limit = length - 32
            while i <= limit {
                v1 = _xxh64_round(v1, _readLE64(buf, i));     i += 8
                v2 = _xxh64_round(v2, _readLE64(buf, i));     i += 8
                v3 = _xxh64_round(v3, _readLE64(buf, i));     i += 8
                v4 = _xxh64_round(v4, _readLE64(buf, i));     i += 8
            }
            let r1: UInt64 = (v1 << 1)  | (v1 >> 63)
            let r2: UInt64 = (v2 << 7)  | (v2 >> 57)
            let r3: UInt64 = (v3 << 12) | (v3 >> 52)
            let r4: UInt64 = (v4 << 18) | (v4 >> 46)
            hash = r1 &+ r2 &+ r3 &+ r4
            hash = _xxh64_mergeRound(hash, v1)
            hash = _xxh64_mergeRound(hash, v2)
            hash = _xxh64_mergeRound(hash, v3)
            hash = _xxh64_mergeRound(hash, v4)
        } else {
            hash = seed &+ p64_5
        }
        hash = hash &+ UInt64(length)
        while i + 8 <= length {
            let lane = _xxh64_round(0, _readLE64(buf, i))
            hash ^= lane
            hash = ((hash << 27) | (hash >> 37)) &* p64_1 &+ p64_4
            i += 8
        }
        if i + 4 <= length {
            let v = UInt64(XXHash._readLE32(buf, i))
            hash ^= v &* p64_1
            hash = ((hash << 23) | (hash >> 41)) &* p64_2 &+ p64_3
            i += 4
        }
        while i < length {
            hash ^= UInt64(buf[i]) &* p64_5
            hash = ((hash << 11) | (hash >> 53)) &* p64_1
            i += 1
        }
        return _xxh64_avalanche(hash)
    }
}

extension XXHash {
    /// Streaming XXH64 digest. Buffers up to 32 bytes of pending input; flushes
    /// a stripe when full; replays the unconsumed tail at finalize time.
    public struct Digest64: Sendable {
        @usableFromInline var v1: UInt64
        @usableFromInline var v2: UInt64
        @usableFromInline var v3: UInt64
        @usableFromInline var v4: UInt64
        @usableFromInline let seed: UInt64
        @usableFromInline var totalLen: UInt64 = 0
        @usableFromInline var buffer: [UInt8] = []

        public init(seed: UInt64 = 0) {
            self.seed = seed
            self.v1 = seed &+ XXHash.p64_1 &+ XXHash.p64_2
            self.v2 = seed &+ XXHash.p64_2
            self.v3 = seed
            self.v4 = seed &- XXHash.p64_1
            self.buffer.reserveCapacity(32)
        }

        public mutating func update(_ bytes: some Sequence<UInt8>) {
            for byte in bytes {
                buffer.append(byte)
                totalLen &+= 1
            }
            while buffer.count >= 32 {
                buffer.withUnsafeBufferPointer { buf in
                    let p = buf.baseAddress!
                    v1 = XXHash._xxh64_round(v1, XXHash._readLE64(p, 0))
                    v2 = XXHash._xxh64_round(v2, XXHash._readLE64(p, 8))
                    v3 = XXHash._xxh64_round(v3, XXHash._readLE64(p, 16))
                    v4 = XXHash._xxh64_round(v4, XXHash._readLE64(p, 24))
                }
                buffer.removeFirst(32)
            }
        }

        public func finalize() -> UInt64 {
            var hash: UInt64
            if totalLen >= 32 {
                let r1: UInt64 = (v1 << 1)  | (v1 >> 63)
                let r2: UInt64 = (v2 << 7)  | (v2 >> 57)
                let r3: UInt64 = (v3 << 12) | (v3 >> 52)
                let r4: UInt64 = (v4 << 18) | (v4 >> 46)
                hash = r1 &+ r2 &+ r3 &+ r4
                hash = XXHash._xxh64_mergeRound(hash, v1)
                hash = XXHash._xxh64_mergeRound(hash, v2)
                hash = XXHash._xxh64_mergeRound(hash, v3)
                hash = XXHash._xxh64_mergeRound(hash, v4)
            } else {
                hash = seed &+ XXHash.p64_5
            }
            hash = hash &+ totalLen
            return buffer.withUnsafeBufferPointer { buf -> UInt64 in
                let p = buf.baseAddress!
                let n = buf.count
                var i = 0
                var h = hash
                while i + 8 <= n {
                    let lane = XXHash._xxh64_round(0, XXHash._readLE64(p, i))
                    h ^= lane
                    h = ((h << 27) | (h >> 37)) &* XXHash.p64_1 &+ XXHash.p64_4
                    i += 8
                }
                if i + 4 <= n {
                    let v = UInt64(XXHash._readLE32(p, i))
                    h ^= v &* XXHash.p64_1
                    h = ((h << 23) | (h >> 41)) &* XXHash.p64_2 &+ XXHash.p64_3
                    i += 4
                }
                while i < n {
                    h ^= UInt64(p[i]) &* XXHash.p64_5
                    h = ((h << 11) | (h >> 53)) &* XXHash.p64_1
                    i += 1
                }
                return XXHash._xxh64_avalanche(h)
            }
        }
    }
}
