# HighwayHash

Google's HighwayHash keyed hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-highwayhash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## HighwayHash-64

HighwayHash, with output size of 64 bits, using a `key` of 4 longs. The key is copied. Throws `IllegalArgumentException` if `key` isn't 4 longs.

```kotlin
val key = longArrayOf(1L, 2L, 3L, 4L)

val hash: ByteArray = HighwayHash.highwayHash64(key = key).hash("Hello, world!")
```

## HighwayHash-128

HighwayHash, with output size of 128 bits, using a `key` of 4 longs. The key is copied. Throws `IllegalArgumentException` if `key` isn't 4 longs.

```kotlin
val key = longArrayOf(1L, 2L, 3L, 4L)

val hash: ByteArray = HighwayHash.highwayHash128(key = key).hash("Hello, world!")
```

## HighwayHash-256

HighwayHash, with output size of 256 bits, using a `key` of 4 longs. The key is copied. Throws `IllegalArgumentException` if `key` isn't 4 longs.

```kotlin
val key = longArrayOf(1L, 2L, 3L, 4L)

val hash: ByteArray = HighwayHash.highwayHash256(key = key).hash("Hello, world!")
```
