// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

@Suite("XXHash.xxh64")
struct XXH64Tests {
    @Test("empty string with seed 0")
    func empty() {
        #expect(XXHash.xxh64([]) == 0xEF46DB3751D8E999)
    }

    @Test("single byte 'a' with seed 0")
    func singleByteA() {
        #expect(XXHash.xxh64(Array("a".utf8)) == 0xD24EC4F1A98C6E5B)
    }

    @Test("'abc' with seed 0")
    func abc() {
        #expect(XXHash.xxh64(Array("abc".utf8)) == 0x44BC2CF5AD770999)
    }

    @Test("32 bytes 0..31 with seed 0")
    func thirtyTwoBytes() {
        let input: [UInt8] = (0..<32).map { UInt8($0) }
        #expect(XXHash.xxh64(input) == 0xCBF59C5116FF32B4)
    }

    @Test("'Hello, World!' (13 bytes) with seed 0")
    func helloWorld() {
        #expect(XXHash.xxh64(Array("Hello, World!".utf8)) == 0xC49AACF8080FE47F)
    }

    @Test("seeded: 'abc' with seed 0xCAFEF00DDEADBEEF")
    func abcSeeded() {
        #expect(XXHash.xxh64(Array("abc".utf8), seed: 0xCAFEF00DDEADBEEF) == 0x354FEFCE7E918157)
    }

    @Test("Sequence input (lazy)")
    func lazySequence() {
        let s = stride(from: UInt8(0), to: UInt8(32), by: 1)
        #expect(XXHash.xxh64(s) == 0xCBF59C5116FF32B4)
    }
}
