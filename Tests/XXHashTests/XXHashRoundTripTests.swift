// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

/// Streaming-equals-one-shot property tests with deterministic pseudo-random input.
/// Foundation-free LCG generator. Coverage spans every XXH3 length boundary
/// including the multi-block long path.
@Suite("XXHash round-trip")
struct XXHashRoundTripTests {
    static func makeBuffer(length: Int) -> [UInt8] {
        var s: UInt64 = 0x9E37_79B9_7F4A_7C15
        var out = [UInt8](repeating: 0, count: length)
        var i = 0
        while i < length {
            s ^= s << 13
            s ^= s >> 7
            s ^= s << 17
            for k in 0..<8 where i + k < length {
                out[i + k] = UInt8((s >> (8 * k)) & 0xFF)
            }
            i += 8
        }
        return out
    }

    static let lengths: [Int] = [
        0, 1, 3, 4, 8, 9, 16, 17, 32, 33, 63, 64, 65,
        127, 128, 129, 239, 240, 241, 256, 1023, 1024, 1025, 4096,
    ]

    static func splits(for n: Int) -> [Int] {
        if n < 64 { return Array(0...n) }
        var s: [Int] = [0]
        var step = 1
        while step < n {
            s.append(step)
            step *= 2
        }
        s.append(n)
        return s
    }

    @Test("XXH32: streaming == one-shot across length × split matrix")
    func xxh32Equiv() {
        for n in Self.lengths {
            let input = Self.makeBuffer(length: n)
            let oneShot = XXHash.xxh32(input, seed: 0xCAFE)
            for split in Self.splits(for: n) {
                var d = XXHash.Digest32(seed: 0xCAFE)
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }

    @Test("XXH64: streaming == one-shot across length × split matrix")
    func xxh64Equiv() {
        for n in Self.lengths {
            let input = Self.makeBuffer(length: n)
            let oneShot = XXHash.xxh64(input, seed: 0xCAFEF00DDEADBEEF)
            for split in Self.splits(for: n) {
                var d = XXHash.Digest64(seed: 0xCAFEF00DDEADBEEF)
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }

    @Test("XXH3-64: streaming == one-shot across length × split matrix")
    func xxh3_64Equiv() {
        for n in Self.lengths {
            let input = Self.makeBuffer(length: n)
            let oneShot = XXHash.xxh3_64(input, seed: 0xCAFEF00DDEADBEEF)
            for split in Self.splits(for: n) {
                var d = XXHash.Digest3_64(seed: 0xCAFEF00DDEADBEEF)
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }

    @Test("XXH3-128: streaming == one-shot across length × split matrix")
    func xxh3_128Equiv() {
        for n in Self.lengths {
            let input = Self.makeBuffer(length: n)
            let oneShot = XXHash.xxh3_128(input, seed: 0xCAFEF00DDEADBEEF)
            for split in Self.splits(for: n) {
                var d = XXHash.Digest3_128(seed: 0xCAFEF00DDEADBEEF)
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }
}
