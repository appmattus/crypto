# BLAKE3

The BLAKE3 hash, with keyed hashing and key derivation modes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-blake3:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Blake3

BLAKE3 with output size of `digestLength` bytes (default: 32 bytes). Throws `IllegalArgumentException` if `digestLength` isn't positive.

```kotlin
val hash: ByteArray = Blake3.blake3().hash("Hello, world!")
val customHash: ByteArray = Blake3.blake3(digestLength = 64).hash("Hello, world!")
```

## Blake3 keyed

BLAKE3 keyed hashing with a 32 byte `key`, with output size of `digestLength` bytes (default: 32 bytes). The key is copied. Throws `IllegalArgumentException` if `key` isn't 32 bytes, or `digestLength` isn't positive.

```kotlin
val key = "0123456789abcdef0123456789abcdef".encodeToByteArray() // 32 bytes

val hash: ByteArray = Blake3.blake3Keyed(key = key, digestLength = 64).hash("Hello, world!")
```

## Blake3 key derivation

BLAKE3 key derivation using `context`, with output size of `digestLength` bytes (default: 32 bytes). The context is copied. Throws `IllegalArgumentException` if `digestLength` isn't positive.

```kotlin
val hash: ByteArray = Blake3.blake3DeriveKey(
    context = "example.com 2026-01-01 session tokens".encodeToByteArray(),
    digestLength = 64
).hash("Hello, world!")
```
