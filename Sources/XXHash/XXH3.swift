// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Copyright (c) 2026 The bare-swift Project Authors.

extension XXHash {
    // MARK: - XXH3 secret + constants
    //
    // Reference: https://github.com/Cyan4973/xxHash/blob/dev/xxh3.h

    @usableFromInline static let xxh3SecretSize = 192
    @usableFromInline static let xxh3StripeLen  = 64
    @usableFromInline static let xxh3SecretConsumeRate = 8
    @usableFromInline static let xxh3AccNB = 8
    @usableFromInline static let xxh3MidSizeMax = 240

    @usableFromInline static let xxh3DefaultSecret: [UInt8] = [
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
        0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
        0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
        0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
        0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
        0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
        0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
        0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
        0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
        0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
        0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
        0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
    ]

    @inlinable
    static func _xxh3_mul32To64(_ a: UInt64, _ b: UInt64) -> UInt64 {
        return (a & 0xFFFFFFFF) &* (b & 0xFFFFFFFF)
    }

    @inlinable
    static func _xxh3_mult64To128(_ lhs: UInt64, _ rhs: UInt64) -> (high: UInt64, low: UInt64) {
        let aL = lhs & 0xFFFFFFFF; let aH = lhs >> 32
        let bL = rhs & 0xFFFFFFFF; let bH = rhs >> 32
        let ll = aL &* bL
        let hl = aH &* bL
        let lh = aL &* bH
        let hh = aH &* bH
        let mid = (ll >> 32) &+ (hl & 0xFFFFFFFF) &+ (lh & 0xFFFFFFFF)
        let low = (mid << 32) | (ll & 0xFFFFFFFF)
        let high = hh &+ (hl >> 32) &+ (lh >> 32) &+ (mid >> 32)
        return (high, low)
    }

    @inlinable
    static func _xxh3_mul128Fold64(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let p = _xxh3_mult64To128(lhs, rhs)
        return p.high ^ p.low
    }

    @inlinable
    static func _xxh3_avalanche(_ h: UInt64) -> UInt64 {
        var h = h
        h ^= h >> 37
        h = h &* 0x165667919E3779F9
        h ^= h >> 32
        return h
    }

    @inlinable
    static func _xxh3_rrmxmx(_ h: UInt64, _ length: UInt64) -> UInt64 {
        var h = h
        h ^= ((h << 49) | (h >> 15)) ^ ((h << 24) | (h >> 40))
        h = h &* 0x9FB21C651E98DF25
        h ^= (h >> 35) &+ length
        h = h &* 0x9FB21C651E98DF25
        h ^= h >> 28
        return h
    }

    @inlinable
    static func _readLE64Secret(_ s: [UInt8], _ i: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<8 {
            v |= UInt64(s[i + k]) << (8 * k)
        }
        return v
    }

    /// Derive the 192-byte custom secret for `seed` (when seed != 0).
    static func _xxh3_customSecret(seed: UInt64) -> [UInt8] {
        if seed == 0 {
            return xxh3DefaultSecret
        }
        var secret = xxh3DefaultSecret
        let nbRounds = xxh3SecretSize / 16
        for i in 0..<nbRounds {
            let lo = _readLE64Secret(secret, 16 * i)        &+ seed
            let hi = _readLE64Secret(secret, 16 * i + 8)    &- seed
            for k in 0..<8 {
                secret[16 * i + k]     = UInt8(truncatingIfNeeded: lo >> (8 * k))
                secret[16 * i + 8 + k] = UInt8(truncatingIfNeeded: hi >> (8 * k))
            }
        }
        return secret
    }

    // MARK: - XXH3 small-input mixers (len <= 240, 64-bit output)

    /// Read a little-endian UInt32 from a [UInt8] secret at offset `i`.
    @inlinable
    static func _readLE32Secret(_ s: [UInt8], _ i: Int) -> UInt32 {
        return UInt32(s[i])
            | (UInt32(s[i+1]) << 8)
            | (UInt32(s[i+2]) << 16)
            | (UInt32(s[i+3]) << 24)
    }

    static func _xxh3_len_1to3_64b(_ input: UnsafePointer<UInt8>, _ len: Int, _ secret: [UInt8], _ seed: UInt64) -> UInt64 {
        let c1 = UInt32(input[0])
        let c2 = UInt32(input[len >> 1])
        let c3 = UInt32(input[len - 1])
        let combined = (c1 << 16) | (c2 << 24) | c3 | (UInt32(len) << 8)
        // C reference: bitflip = (readLE32(secret) ^ readLE32(secret+4)) + seed
        let bitflip = UInt64(_readLE32Secret(secret, 0) ^ _readLE32Secret(secret, 4)) &+ seed
        let keyed = UInt64(combined) ^ bitflip
        return _xxh64_avalanche(keyed)
    }

    static func _xxh3_len_4to8_64b(_ input: UnsafePointer<UInt8>, _ len: Int, _ secret: [UInt8], _ seed: UInt64) -> UInt64 {
        let s = seed ^ (UInt64(UInt32(seed & 0xFFFFFFFF).byteSwapped) << 32)
        let input1 = UInt64(_readLE32(input, 0))
        let input2 = UInt64(_readLE32(input, len - 4))
        let bitflip = (_readLE64Secret(secret, 8) ^ _readLE64Secret(secret, 16)) &- s
        let inp64 = input2 | (input1 << 32)
        let keyed = inp64 ^ bitflip
        return _xxh3_rrmxmx(keyed, UInt64(len))
    }

    static func _xxh3_len_9to16_64b(_ input: UnsafePointer<UInt8>, _ len: Int, _ secret: [UInt8], _ seed: UInt64) -> UInt64 {
        let bitflip1 = (_readLE64Secret(secret, 24) ^ _readLE64Secret(secret, 32)) &+ seed
        let bitflip2 = (_readLE64Secret(secret, 40) ^ _readLE64Secret(secret, 48)) &- seed
        let inputLo = _readLE64(input, 0)         ^ bitflip1
        let inputHi = _readLE64(input, len - 8)   ^ bitflip2
        let acc = UInt64(len) &+ inputLo.byteSwapped &+ inputHi &+ _xxh3_mul128Fold64(inputLo, inputHi)
        return _xxh3_avalanche(acc)
    }

    static func _xxh3_len_0to16_64b(_ input: UnsafePointer<UInt8>, _ len: Int, _ secret: [UInt8], _ seed: UInt64) -> UInt64 {
        if len > 8  { return _xxh3_len_9to16_64b(input, len, secret, seed) }
        if len >= 4 { return _xxh3_len_4to8_64b(input, len, secret, seed) }
        if len > 0  { return _xxh3_len_1to3_64b(input, len, secret, seed) }
        // Empty path uses XXH64_avalanche per the C reference.
        return _xxh64_avalanche(seed ^ _readLE64Secret(secret, 56) ^ _readLE64Secret(secret, 64))
    }

    @inlinable
    static func _xxh3_mix16B(_ input: UnsafePointer<UInt8>, _ inputOffset: Int, _ secret: [UInt8], _ secretOffset: Int, _ seed: UInt64) -> UInt64 {
        let inputLo = _readLE64(input, inputOffset)
        let inputHi = _readLE64(input, inputOffset + 8)
        let kLo = _readLE64Secret(secret, secretOffset)
        let kHi = _readLE64Secret(secret, secretOffset + 8)
        return _xxh3_mul128Fold64(inputLo ^ (kLo &+ seed), inputHi ^ (kHi &- seed))
    }

    static func _xxh3_len_17to128_64b(_ input: UnsafePointer<UInt8>, _ len: Int, _ secret: [UInt8], _ seed: UInt64) -> UInt64 {
        var acc: UInt64 = UInt64(len) &* p64_1
        if len > 32 {
            if len > 64 {
                if len > 96 {
                    acc &+= _xxh3_mix16B(input, 48,        secret, 96, seed)
                    acc &+= _xxh3_mix16B(input, len - 64,  secret, 112, seed)
                }
                acc &+= _xxh3_mix16B(input, 32,            secret, 64, seed)
                acc &+= _xxh3_mix16B(input, len - 48,      secret, 80, seed)
            }
            acc &+= _xxh3_mix16B(input, 16,                secret, 32, seed)
            acc &+= _xxh3_mix16B(input, len - 32,          secret, 48, seed)
        }
        acc &+= _xxh3_mix16B(input, 0,                     secret, 0,  seed)
        acc &+= _xxh3_mix16B(input, len - 16,              secret, 16, seed)
        return _xxh3_avalanche(acc)
    }

    static func _xxh3_len_129to240_64b(_ input: UnsafePointer<UInt8>, _ len: Int, _ secret: [UInt8], _ seed: UInt64) -> UInt64 {
        let nbRounds = len / 16
        var acc: UInt64 = UInt64(len) &* p64_1
        for i in 0..<8 {
            acc &+= _xxh3_mix16B(input, 16 * i, secret, 16 * i, seed)
        }
        acc = _xxh3_avalanche(acc)
        for i in 8..<nbRounds {
            acc &+= _xxh3_mix16B(input, 16 * i, secret, 16 * (i - 8) + 3, seed)
        }
        // C reference uses XXH3_SECRETSIZE_MIN (136), not the full 192-byte secret size.
        acc &+= _xxh3_mix16B(input, len - 16, secret, 136 - 17, seed)
        return _xxh3_avalanche(acc)
    }

    // MARK: - XXH3 long-input accumulator path

    @inlinable
    static func _xxh3_accumulate_512(_ acc: inout [UInt64], _ input: UnsafePointer<UInt8>, _ inputOffset: Int, _ secret: [UInt8], _ secretOffset: Int) {
        for i in 0..<xxh3AccNB {
            let dataVal = _readLE64(input, inputOffset + 8 * i)
            let dataKey = dataVal ^ _readLE64Secret(secret, secretOffset + 8 * i)
            acc[i ^ 1] &+= dataVal
            acc[i]     &+= _xxh3_mul32To64(dataKey, dataKey >> 32)
        }
    }

    static func _xxh3_accumulate(_ acc: inout [UInt64], _ input: UnsafePointer<UInt8>, _ inputOffset: Int, _ secret: [UInt8], _ secretOffsetStart: Int, _ nbStripes: Int) {
        for n in 0..<nbStripes {
            _xxh3_accumulate_512(&acc, input, inputOffset + n * xxh3StripeLen, secret, secretOffsetStart + n * xxh3SecretConsumeRate)
        }
    }

    @inlinable
    static func _xxh3_scrambleAcc(_ acc: inout [UInt64], _ secret: [UInt8]) {
        let secretOffset = xxh3SecretSize - xxh3StripeLen
        for i in 0..<xxh3AccNB {
            let key64 = _readLE64Secret(secret, secretOffset + 8 * i)
            var v = acc[i]
            v ^= v >> 47
            v ^= key64
            v &*= UInt64(p32_1)
            acc[i] = v
        }
    }

    @inlinable
    static func _xxh3_mix2Accs(_ acc: [UInt64], _ accOffset: Int, _ secret: [UInt8], _ secretOffset: Int) -> UInt64 {
        return _xxh3_mul128Fold64(
            acc[accOffset]     ^ _readLE64Secret(secret, secretOffset),
            acc[accOffset + 1] ^ _readLE64Secret(secret, secretOffset + 8)
        )
    }

    static func _xxh3_mergeAccs64(_ acc: [UInt64], _ secret: [UInt8], _ secretOffsetStart: Int, _ start: UInt64) -> UInt64 {
        var result = start
        result &+= _xxh3_mix2Accs(acc, 0, secret, secretOffsetStart)
        result &+= _xxh3_mix2Accs(acc, 2, secret, secretOffsetStart + 16)
        result &+= _xxh3_mix2Accs(acc, 4, secret, secretOffsetStart + 32)
        result &+= _xxh3_mix2Accs(acc, 6, secret, secretOffsetStart + 48)
        return _xxh3_avalanche(result)
    }

    static func _xxh3_initialAcc() -> [UInt64] {
        return [
            UInt64(p32_3), p64_1, p64_2, p64_3,
            p64_4, UInt64(p32_2), p64_5, UInt64(p32_1),
        ]
    }

    static func _xxh3_hashLong_64b(_ input: UnsafePointer<UInt8>, _ len: Int, _ secret: [UInt8]) -> UInt64 {
        var acc = _xxh3_initialAcc()
        let stripesPerBlock = (xxh3SecretSize - xxh3StripeLen) / xxh3SecretConsumeRate
        let blockLen = stripesPerBlock * xxh3StripeLen
        let nbBlocks = (len - 1) / blockLen
        for block in 0..<nbBlocks {
            _xxh3_accumulate(&acc, input, block * blockLen, secret, 0, stripesPerBlock)
            _xxh3_scrambleAcc(&acc, secret)
        }
        let trailingLen = len - nbBlocks * blockLen
        let nbStripes = (trailingLen - 1) / xxh3StripeLen
        _xxh3_accumulate(&acc, input, nbBlocks * blockLen, secret, 0, nbStripes)
        _xxh3_accumulate_512(&acc, input, len - xxh3StripeLen, secret, xxh3SecretSize - xxh3StripeLen - 7)
        return _xxh3_mergeAccs64(acc, secret, 11, UInt64(len) &* p64_1)
    }

    /// `customSecret` is only used for the long path; small-input paths always
    /// use the default secret with the seed passed as a separate argument
    /// (matches XXH3_64bits_withSeed_internal in the C reference).
    static func _xxh3_64bits_internal(_ input: UnsafePointer<UInt8>, _ len: Int, _ seed: UInt64, _ customSecret: [UInt8]) -> UInt64 {
        if len <= 16  { return _xxh3_len_0to16_64b(input, len, xxh3DefaultSecret, seed) }
        if len <= 128 { return _xxh3_len_17to128_64b(input, len, xxh3DefaultSecret, seed) }
        if len <= xxh3MidSizeMax { return _xxh3_len_129to240_64b(input, len, xxh3DefaultSecret, seed) }
        return _xxh3_hashLong_64b(input, len, customSecret)
    }
}
