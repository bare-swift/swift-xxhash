# Test-parity exceptions

Per [RFC-0002](https://github.com/bare-swift/bare-swift/blob/main/rfcs/0002-test-parity-policy.md), this file documents why some upstream test cases are not extracted as fixtures.

## Source: `twox-hash` (Rust crate)

`twox-hash` uses inline `#[test]` cases plus `proptest`-driven random round-trip
coverage. The Swift translation:

- Known-answer vectors: hand-coded inline in `XXH32Tests.swift`, `XXH64Tests.swift`,
  `XXH3_64Tests.swift`, and `XXH3_128Tests.swift`. Values were generated from the
  canonical C reference using `xxhsum` (see "Vector regeneration" below).
- Round-trip property tests: translated to deterministic pseudo-random streaming-
  equals-one-shot tests in `XXHashRoundTripTests.swift` (no Foundation, fixed LCG).

## Source: `Cyan4973/xxHash` (C reference)

The C reference ships a `xxhsum --bench` performance harness and a sanity-check
suite written in C; neither is extractable as data fixtures. Our vectors are
generated *from* this C reference, which is the strongest possible parity guarantee.

## Vector regeneration

The known-answer vectors baked into the Swift test files were generated from
xxhsum 0.8.x. To regenerate when the upstream xxhsum advances a major version
(it should not change the algorithm — these are stable), recompute by piping
each input through `xxhsum -H32`, `-H64`, `-H3`, `-H128` with both seed=0 and
seed=0xCAFEF00DDEADBEEF and replace the constants in the test files.

## Refresh

Record source commits here when refreshing:

- `twox-hash`: tracked at upstream commit (record at next refresh)
- `Cyan4973/xxHash`: tracked at upstream commit (record at next refresh)
