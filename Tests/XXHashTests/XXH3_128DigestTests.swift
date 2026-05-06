// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

@Suite("XXHash.Digest3_128")
struct XXH3_128DigestTests {
    @Test("empty digest equals one-shot empty")
    func empty() {
        let d = XXHash.Digest3_128()
        #expect(d.finalize() == XXHash.xxh3_128([] as [UInt8]))
    }

    @Test("single update equals one-shot, sub-stripe input")
    func singleSmall() {
        var d = XXHash.Digest3_128()
        d.update("abc".utf8)
        #expect(d.finalize() == XXHash.xxh3_128(Array("abc".utf8)))
    }

    @Test("multiple updates equal one-shot, mid-input length 96")
    func multiMid() {
        let input: [UInt8] = (0..<96).map { UInt8($0) }
        var d = XXHash.Digest3_128()
        d.update(input.prefix(40))
        d.update(input.dropFirst(40))
        #expect(d.finalize() == XXHash.xxh3_128(input))
    }

    @Test("multiple updates equal one-shot, long input length 1500")
    func multiLong() {
        let input: [UInt8] = (0..<1500).map { UInt8($0 & 0xFF) }
        let oneShot = XXHash.xxh3_128(input)
        var d = XXHash.Digest3_128()
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
        let oneShot = XXHash.xxh3_128(input, seed: 0xCAFEF00DDEADBEEF)
        var d = XXHash.Digest3_128(seed: 0xCAFEF00DDEADBEEF)
        d.update(input.prefix(100))
        d.update(input.dropFirst(100))
        #expect(d.finalize() == oneShot)
    }

    @Test("split at every byte boundary equals one-shot, for inputs 0..<200")
    func boundarySplits() {
        for n in 0..<200 {
            let input = (0..<n).map { UInt8($0 & 0xFF) }
            let oneShot = XXHash.xxh3_128(input)
            for split in 0...n {
                var d = XXHash.Digest3_128()
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }
}
