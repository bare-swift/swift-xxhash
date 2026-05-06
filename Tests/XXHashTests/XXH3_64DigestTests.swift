// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

@Suite("XXHash.Digest3_64")
struct XXH3_64DigestTests {
    @Test("empty digest equals one-shot empty")
    func empty() {
        let d = XXHash.Digest3_64()
        #expect(d.finalize() == XXHash.xxh3_64([] as [UInt8]))
    }

    @Test("single update equals one-shot, sub-stripe input")
    func singleSmall() {
        var d = XXHash.Digest3_64()
        d.update("abc".utf8)
        #expect(d.finalize() == XXHash.xxh3_64(Array("abc".utf8)))
    }

    @Test("multiple updates equal one-shot, mid-input length 64")
    func multiMid() {
        let input: [UInt8] = (0..<64).map { UInt8($0) }
        var d = XXHash.Digest3_64()
        d.update(input.prefix(20))
        d.update(input.dropFirst(20).prefix(15))
        d.update(input.dropFirst(35))
        #expect(d.finalize() == XXHash.xxh3_64(input))
    }

    @Test("multiple updates equal one-shot, long input length 1500")
    func multiLong() {
        let input: [UInt8] = (0..<1500).map { UInt8($0 & 0xFF) }
        let oneShot = XXHash.xxh3_64(input)
        var d = XXHash.Digest3_64()
        d.update(input.prefix(7))
        d.update(input.dropFirst(7).prefix(57))
        d.update(input.dropFirst(64).prefix(960))
        d.update(input.dropFirst(1024).prefix(64))
        d.update(input.dropFirst(1088))
        #expect(d.finalize() == oneShot)
    }

    @Test("seeded streaming")
    func seeded() {
        let input: [UInt8] = (0..<300).map { UInt8($0 & 0xFF) }
        let oneShot = XXHash.xxh3_64(input, seed: 0xCAFEF00DDEADBEEF)
        var d = XXHash.Digest3_64(seed: 0xCAFEF00DDEADBEEF)
        d.update(input.prefix(100))
        d.update(input.dropFirst(100))
        #expect(d.finalize() == oneShot)
    }

    @Test("split at every byte boundary equals one-shot, for inputs 0..<200")
    func boundarySplits() {
        for n in 0..<200 {
            let input = (0..<n).map { UInt8($0 & 0xFF) }
            let oneShot = XXHash.xxh3_64(input)
            for split in 0...n {
                var d = XXHash.Digest3_64()
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }
}
