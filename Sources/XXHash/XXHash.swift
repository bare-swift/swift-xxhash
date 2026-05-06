// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Copyright (c) 2026 The bare-swift Project Authors.

/// Sendable, Foundation-free xxHash (XXH32, XXH64, XXH3-64, XXH3-128).
///
/// Wire-compatible with the upstream C reference (`xxhsum`) and the
/// `twox-hash` Rust crate. Use the one-shot helpers (``xxh32(_:seed:)``,
/// ``xxh64(_:seed:)``, ``xxh3_64(_:seed:)``, ``xxh3_128(_:seed:)``) for
/// single-buffer hashing, or the streaming ``Digest32`` / ``Digest64`` /
/// ``Digest3_64`` / ``Digest3_128`` value types when input arrives in
/// pieces.
public enum XXHash: Sendable {}
