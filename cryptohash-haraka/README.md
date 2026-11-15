# Haraka

The Haraka v2 short-input hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-haraka:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Haraka-256

Haraka-256 v2, hashing a 256-bit input to 256 bits.

```kotlin
val input = ByteArray(32) { it.toByte() } // exactly 32 bytes

val hash: ByteArray = Haraka.haraka256.hash(input)
```

## Haraka-512

Haraka-512 v2, hashing a 512-bit input to 256 bits.

```kotlin
val input = ByteArray(64) { it.toByte() } // exactly 64 bytes

val hash: ByteArray = Haraka.haraka512.hash(input)
```
