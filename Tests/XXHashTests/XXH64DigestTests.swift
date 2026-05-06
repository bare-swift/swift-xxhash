// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

@Suite("XXHash.Digest64")
struct XXH64DigestTests {
    @Test("empty Digest64 finalizes to xxh64 of empty input")
    func empty() {
        let d = XXHash.Digest64()
        #expect(d.finalize() == XXHash.xxh64([] as [UInt8]))
    }

    @Test("single update equals one-shot")
    func singleUpdate() {
        var d = XXHash.Digest64()
        d.update("abc".utf8)
        #expect(d.finalize() == XXHash.xxh64(Array("abc".utf8)))
    }

    @Test("multiple updates equal one-shot, crossing 32-byte stripe boundary")
    func multipleUpdates() {
        let s = "The quick brown fox jumps over the lazy dog."
        var d = XXHash.Digest64()
        d.update("The quick brown ".utf8)
        d.update("fox jumps over ".utf8)
        d.update("the lazy dog.".utf8)
        #expect(d.finalize() == XXHash.xxh64(Array(s.utf8)))
    }

    @Test("seed flows through")
    func seeded() {
        var d = XXHash.Digest64(seed: 0xCAFEF00DDEADBEEF)
        d.update("abc".utf8)
        #expect(d.finalize() == XXHash.xxh64(Array("abc".utf8), seed: 0xCAFEF00DDEADBEEF))
    }

    @Test("split at every byte boundary equals one-shot, for inputs 0..<96")
    func boundarySplits() {
        for n in 0..<96 {
            let input = (0..<n).map { UInt8($0 & 0xFF) }
            let oneShot = XXHash.xxh64(input)
            for split in 0...n {
                var d = XXHash.Digest64()
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }
}
