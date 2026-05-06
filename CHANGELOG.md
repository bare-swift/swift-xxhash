# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-05-06

### Added
- `XXHash.xxh32(_:seed:)`, `XXHash.xxh64(_:seed:)`, `XXHash.xxh3_64(_:seed:)`, `XXHash.xxh3_128(_:seed:)` — one-shot hash functions for all four xxHash variants. Wire-compatible with the C reference (`xxhsum`) and the `twox-hash` Rust crate.
- `XXHash.Digest32`, `XXHash.Digest64`, `XXHash.Digest3_64`, `XXHash.Digest3_128` — streaming value-typed digests (mutating `update(_:)`, non-mutating `finalize()`).
- `XXHash.Hash128` — 128-bit result struct with `high` / `low` UInt64 fields, big-endian `bytes`, and 32-char lowercase hex `description`.
- DocC documentation, full README example, NOTICE crediting upstream `twox-hash` and `Cyan4973/xxHash`.

### Limitations (out of scope for v0.1)
- XXH3 caller-provided custom secret. Defer to v0.2.
- Canonical big-endian byte forms for XXH32/XXH64. Native UInt return is sufficient for v0.1.
- SIMD specializations (SSE2/AVX2/NEON). Pure scalar in v0.1; algorithm constants unchanged when SIMD lands later.
- `swift.Hashable` / stdlib `Hasher` integration.
