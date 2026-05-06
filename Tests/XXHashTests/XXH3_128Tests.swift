// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

/// Reference values from xxhsum 0.8.3 / Python xxhash 3.7.0 (cross-verified).
@Suite("XXHash.xxh3_128")
struct XXH3_128Tests {
    @Test("empty input")
    func empty() {
        let h = XXHash.xxh3_128([])
        #expect(h.high == 0x99AA06D3014798D8)
        #expect(h.low  == 0x6001C324468D497F)
    }

    @Test("'a' (len 1)")
    func len1() {
        let h = XXHash.xxh3_128(Array("a".utf8))
        #expect(h.high == 0xA96FAF705AF16834)
        #expect(h.low  == 0xE6C632B61E964E1F)
    }

    @Test("'abc' (len 3)")
    func abc() {
        let h = XXHash.xxh3_128(Array("abc".utf8))
        #expect(h.high == 0x06B05AB6733A6185)
        #expect(h.low  == 0x78AF5F94892F3950)
    }

    @Test("'abcd' (len 4)")
    func len4() {
        let h = XXHash.xxh3_128(Array("abcd".utf8))
        #expect(h.high == 0x8D6B60383DFA90C2)
        #expect(h.low  == 0x1BE79EECD1B1353D)
    }

    @Test("'abcdefgh' (len 8)")
    func len8() {
        let h = XXHash.xxh3_128(Array("abcdefgh".utf8))
        #expect(h.high == 0xDAC23237AF373533)
        #expect(h.low  == 0x42B702B313880F12)
    }

    @Test("16 bytes 0..15")
    func len16() {
        let input: [UInt8] = (0..<16).map { UInt8($0) }
        let h = XXHash.xxh3_128(input)
        #expect(h.high == 0x72950631827607E2)
        #expect(h.low  == 0x842812CC870DCAE2)
    }

    @Test("64 bytes 0..63")
    func len64() {
        let input: [UInt8] = (0..<64).map { UInt8($0) }
        let h = XXHash.xxh3_128(input)
        #expect(h.high == 0x9C6E140A465545E5)
        #expect(h.low  == 0x90C1971DDB04CE74)
    }

    @Test("128 bytes 0..127")
    func len128() {
        let input: [UInt8] = (0..<128).map { UInt8($0) }
        let h = XXHash.xxh3_128(input)
        #expect(h.high == 0x14792FC3AF88DC6C)
        #expect(h.low  == 0x05321A0B64D67B41)
    }

    @Test("129 bytes (mid+ path)")
    func len129() {
        let input: [UInt8] = (0..<129).map { UInt8($0 & 0xFF) }
        let h = XXHash.xxh3_128(input)
        #expect(h.high == 0xDD5E74AC6B45F54E)
        #expect(h.low  == 0xBC30B63382B09A3B)
    }

    @Test("240 bytes (mid+ path upper)")
    func len240() {
        let input: [UInt8] = (0..<240).map { UInt8($0 & 0xFF) }
        let h = XXHash.xxh3_128(input)
        #expect(h.high == 0x65B5BE86DA5540E7)
        #expect(h.low  == 0xC92B68E16F83BBB6)
    }

    @Test("256 bytes (long-path)")
    func len256() {
        let input: [UInt8] = (0..<256).map { UInt8($0 & 0xFF) }
        let h = XXHash.xxh3_128(input)
        #expect(h.high == 0xF1F8A93F50849AC3)
        #expect(h.low  == 0x9408A4433B952D71)
    }

    @Test("1024 bytes (one full block)")
    func len1024() {
        let input: [UInt8] = (0..<1024).map { UInt8($0 & 0xFF) }
        let h = XXHash.xxh3_128(input)
        #expect(h.high == 0x83885E853BB6640C)
        #expect(h.low  == 0xA870F92984398D22)
    }

    @Test("seeded: 'abc' with seed 0xCAFEF00DDEADBEEF")
    func seededAbc() {
        let h = XXHash.xxh3_128(Array("abc".utf8), seed: 0xCAFEF00DDEADBEEF)
        #expect(h.high == 0xA741CB513C6B7843)
        #expect(h.low  == 0x1461A612AE58339A)
    }

    @Test("seeded long: 1024 bytes with seed 0xCAFEF00DDEADBEEF")
    func seededLong() {
        let input: [UInt8] = (0..<1024).map { UInt8($0 & 0xFF) }
        let h = XXHash.xxh3_128(input, seed: 0xCAFEF00DDEADBEEF)
        #expect(h.high == 0x0F9357CA70937EF4)
        #expect(h.low  == 0xBBFA1FF7EC3BD5F3)
    }
}
