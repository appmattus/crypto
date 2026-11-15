# xxHash

The xxHash family of fast, non-cryptographic hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-xxhash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## xxHash-32

XXH32 with output size of 32 bits.

```kotlin
val hash: ByteArray = XxHash.xxh32().hash("Hello, world!")
val customHash: ByteArray = XxHash.xxh32(seed = 1).hash("Hello, world!")
```

## xxHash-64

XXH64 with output size of 64 bits.

```kotlin
val hash: ByteArray = XxHash.xxh64().hash("Hello, world!")
val customHash: ByteArray = XxHash.xxh64(seed = 1L).hash("Hello, world!")
```

## xxHash3-64

XXH3 with output size of 64 bits.

```kotlin
val secret = ByteArray(136) { it.toByte() } // at least 136 bytes

val hash: ByteArray = XxHash.xxh3_64().hash("Hello, world!")
val hashWithSeed: ByteArray = XxHash.xxh3_64(seed = 1L).hash("Hello, world!")
val hashWithSecret: ByteArray = XxHash.xxh3_64(secret = secret).hash("Hello, world!")
```

## xxHash3-128

XXH3 with output size of 128 bits.

```kotlin
val secret = ByteArray(136) { it.toByte() } // at least 136 bytes

val hash: ByteArray = XxHash.xxh3_128().hash("Hello, world!")
val hashWithSeed: ByteArray = XxHash.xxh3_128(seed = 1L).hash("Hello, world!")
val hashWithSecret: ByteArray = XxHash.xxh3_128(secret = secret).hash("Hello, world!")
```
