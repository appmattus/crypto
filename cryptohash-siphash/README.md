# SipHash

The SipHash keyed hashes, with configurable rounds.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-siphash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## SipHash

SipHash, with output size of 64 bits, using a 16 byte `key`, `compressionRounds` compression rounds and `finalizationRounds` finalization rounds (default: SipHash-2-4). The key is copied. Throws `IllegalArgumentException` if `key` isn't 16 bytes, or either round count isn't positive.

```kotlin
val key = "0123456789abcdef".encodeToByteArray() // 16 bytes

val hash: ByteArray = SipHash.sipHash(
    key = key,
    compressionRounds = 1,
    finalizationRounds = 3
).hash("Hello, world!")
```

## SipHash128

SipHash128, with output size of 128 bits, using a 16 byte `key`, `compressionRounds` compression rounds and `finalizationRounds` finalization rounds (default: SipHash128-2-4). The key is copied. Throws `IllegalArgumentException` if `key` isn't 16 bytes, or either round count isn't positive.

```kotlin
val key = "0123456789abcdef".encodeToByteArray() // 16 bytes

val hash: ByteArray = SipHash.sipHash128(
    key = key,
    compressionRounds = 1,
    finalizationRounds = 3
).hash("Hello, world!")
```
