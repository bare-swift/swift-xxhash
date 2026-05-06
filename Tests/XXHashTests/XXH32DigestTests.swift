// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import Testing
@testable import XXHash

@Suite("XXHash.Digest32")
struct XXH32DigestTests {
    @Test("empty Digest32 finalizes to xxh32 of empty input")
    func empty() {
        let d = XXHash.Digest32()
        #expect(d.finalize() == XXHash.xxh32([] as [UInt8]))
    }

    @Test("single update equals one-shot")
    func singleUpdate() {
        var d = XXHash.Digest32()
        d.update("abc".utf8)
        #expect(d.finalize() == XXHash.xxh32(Array("abc".utf8)))
    }

    @Test("multiple updates equal one-shot")
    func multipleUpdates() {
        var d = XXHash.Digest32()
        d.update("Hello, ".utf8)
        d.update("World!".utf8)
        #expect(d.finalize() == XXHash.xxh32(Array("Hello, World!".utf8)))
    }

    @Test("seed flows through")
    func seeded() {
        var d = XXHash.Digest32(seed: 0xCAFE)
        d.update("abc".utf8)
        #expect(d.finalize() == XXHash.xxh32(Array("abc".utf8), seed: 0xCAFE))
    }

    @Test("split at every byte boundary equals one-shot, for inputs of size 0..<48")
    func boundarySplits() {
        for n in 0..<48 {
            let input = (0..<n).map { UInt8($0 & 0xFF) }
            let oneShot = XXHash.xxh32(input)
            for split in 0...n {
                var d = XXHash.Digest32()
                d.update(input.prefix(split))
                d.update(input.suffix(n - split))
                #expect(d.finalize() == oneShot, "n=\(n) split=\(split)")
            }
        }
    }
}
