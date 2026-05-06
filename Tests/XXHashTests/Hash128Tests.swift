// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

@Suite("XXHash.Hash128")
struct Hash128Tests {
    @Test("Hash128 stores high and low UInt64 fields")
    func fields() {
        let h = XXHash.Hash128(high: 0x0123456789ABCDEF, low: 0xFEDCBA9876543210)
        #expect(h.high == 0x0123456789ABCDEF)
        #expect(h.low  == 0xFEDCBA9876543210)
    }

    @Test("Hash128.bytes is 16 bytes, big-endian, high word first")
    func bytesBigEndian() {
        let h = XXHash.Hash128(high: 0x0011223344556677, low: 0x8899AABBCCDDEEFF)
        let expected: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ]
        #expect(h.bytes == expected)
    }

    @Test("Hash128.description is 32 lowercase hex chars")
    func description() {
        let h = XXHash.Hash128(high: 0x0011223344556677, low: 0x8899AABBCCDDEEFF)
        #expect(h.description == "00112233445566778899aabbccddeeff")
    }

    @Test("Hash128 is Hashable + Equatable")
    func conformances() {
        let a = XXHash.Hash128(high: 1, low: 2)
        let b = XXHash.Hash128(high: 1, low: 2)
        let c = XXHash.Hash128(high: 1, low: 3)
        #expect(a == b)
        #expect(a != c)
        var set = Set<XXHash.Hash128>()
        set.insert(a)
        #expect(set.contains(b))
    }

    @Test("Hash128 is Sendable")
    func sendable() {
        let _: any Sendable = XXHash.Hash128(high: 0, low: 0)
    }
}
