// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Copyright (c) 2026 The bare-swift Project Authors.

extension XXHash {
    /// 128-bit hash value produced by ``XXHash/xxh3_128(_:seed:)`` and
    /// ``XXHash/Digest3_128``. Mirrors the C reference's `XXH128_hash_t`.
    public struct Hash128: Sendable, Hashable, CustomStringConvertible {
        public let high: UInt64
        public let low: UInt64

        public init(high: UInt64, low: UInt64) {
            self.high = high
            self.low = low
        }

        /// 16 bytes, big-endian, high word followed by low word.
        public var bytes: [UInt8] {
            var out = [UInt8](repeating: 0, count: 16)
            for i in 0..<8 {
                out[i]     = UInt8((high >> (56 - 8 * i)) & 0xFF)
                out[8 + i] = UInt8((low  >> (56 - 8 * i)) & 0xFF)
            }
            return out
        }

        /// 32 lowercase hex characters.
        public var description: String {
            let hex: [Character] = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
            var out = ""
            out.reserveCapacity(32)
            for b in bytes {
                out.append(hex[Int(b >> 4)])
                out.append(hex[Int(b & 0x0F)])
            }
            return out
        }
    }
}
