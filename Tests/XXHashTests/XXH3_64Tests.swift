// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

/// Reference values from xxhsum 0.8.3 / Python xxhash 3.7.0 (cross-verified).
@Suite("XXHash.xxh3_64 (small inputs, len <= 240)")
struct XXH3_64Tests {
    @Test("empty input (len 0)")
    func empty() {
        #expect(XXHash.xxh3_64([]) == 0x2D06800538D394C2)
    }

    @Test("'a' (len 1)")
    func len1() {
        #expect(XXHash.xxh3_64(Array("a".utf8)) == 0xE6C632B61E964E1F)
    }

    @Test("'abc' (len 3)")
    func len3() {
        #expect(XXHash.xxh3_64(Array("abc".utf8)) == 0x78AF5F94892F3950)
    }

    @Test("'abcd' (len 4)")
    func len4() {
        #expect(XXHash.xxh3_64(Array("abcd".utf8)) == 0x6497A96F53A89890)
    }

    @Test("'abcdefgh' (len 8)")
    func len8() {
        #expect(XXHash.xxh3_64(Array("abcdefgh".utf8)) == 0x6F45A76842A96483)
    }

    @Test("16 bytes 0..15 (len 16)")
    func len16() {
        let input: [UInt8] = (0..<16).map { UInt8($0) }
        #expect(XXHash.xxh3_64(input) == 0x8355E3A6F61770DB)
    }

    @Test("'The quick brown fox' (len 19)")
    func len19() {
        #expect(XXHash.xxh3_64(Array("The quick brown fox".utf8)) == 0xF8B92649FD8122B4)
    }

    @Test("64 bytes 0..63 (len 64)")
    func len64() {
        let input: [UInt8] = (0..<64).map { UInt8($0) }
        #expect(XXHash.xxh3_64(input) == 0x6187EB9089B0ED55)
    }

    @Test("128 bytes 0..127 (len 128 — mid path edge)")
    func len128() {
        let input: [UInt8] = (0..<128).map { UInt8($0) }
        #expect(XXHash.xxh3_64(input) == 0x85C6174C7FF4C46B)
    }

    @Test("129 bytes (mid+ path entry)")
    func len129() {
        let input: [UInt8] = (0..<129).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input) == 0xEC7642B431BA3E5A)
    }

    @Test("240 bytes (mid+ path upper bound)")
    func len240() {
        let input: [UInt8] = (0..<240).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input) == 0x375A384D957FE865)
    }

    @Test("seeded: 'abc' with seed 0xCAFEF00DDEADBEEF")
    func seededAbc() {
        #expect(XXHash.xxh3_64(Array("abc".utf8), seed: 0xCAFEF00DDEADBEEF) == 0x1461A612AE58339A)
    }
}

@Suite("XXHash.xxh3_64 (long inputs, len > 240)")
struct XXH3_64LongTests {
    @Test("241 bytes (just past mid+ boundary)")
    func len241() {
        let input: [UInt8] = (0..<241).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input) == 0x02E8CD95421C6D02)
    }

    @Test("256 bytes")
    func len256() {
        let input: [UInt8] = (0..<256).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input) == 0x9408A4433B952D71)
    }

    @Test("1024 bytes (one full block)")
    func len1024() {
        let input: [UInt8] = (0..<1024).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input) == 0xA870F92984398D22)
    }

    @Test("1025 bytes (block + 1)")
    func len1025() {
        let input: [UInt8] = (0..<1025).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input) == 0x78C86E91EE939852)
    }

    @Test("4096 bytes")
    func len4096() {
        let input: [UInt8] = (0..<4096).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input) == 0xEB4B7C3707879151)
    }

    @Test("seeded long: 1024 bytes with seed 0xCAFEF00DDEADBEEF")
    func seededLong() {
        let input: [UInt8] = (0..<1024).map { UInt8($0 & 0xFF) }
        #expect(XXHash.xxh3_64(input, seed: 0xCAFEF00DDEADBEEF) == 0xBBFA1FF7EC3BD5F3)
    }
}
