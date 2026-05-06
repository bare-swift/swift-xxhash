// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

/// Reference values generated from xxhsum 0.8.3 / Python xxhash 3.7.0
/// (cross-verified). Both produce identical output.
@Suite("XXHash.xxh32")
struct XXH32Tests {
    @Test("empty string with seed 0")
    func empty() {
        #expect(XXHash.xxh32([]) == 0x02CC5D05)
    }

    @Test("single byte 'a' with seed 0")
    func singleByteA() {
        #expect(XXHash.xxh32(Array("a".utf8)) == 0x550D7456)
    }

    @Test("'abc' with seed 0")
    func abc() {
        #expect(XXHash.xxh32(Array("abc".utf8)) == 0x32D153FF)
    }

    @Test("16 bytes 0..15 with seed 0")
    func sixteenBytes() {
        let input: [UInt8] = (0..<16).map { UInt8($0) }
        #expect(XXHash.xxh32(input) == 0xB72837F4)
    }

    @Test("'Hello, World!' (13 bytes — sub-stripe) with seed 0")
    func helloWorld() {
        #expect(XXHash.xxh32(Array("Hello, World!".utf8)) == 0x4007DE50)
    }

    @Test("seeded: 'abc' with seed 0xCAFE")
    func abcSeeded() {
        #expect(XXHash.xxh32(Array("abc".utf8), seed: 0xCAFE) == 0xEF0FCA86)
    }

    @Test("Sequence input (lazy)")
    func lazySequence() {
        let s = stride(from: UInt8(0), to: UInt8(16), by: 1)
        #expect(XXHash.xxh32(s) == 0xB72837F4)
    }
}
