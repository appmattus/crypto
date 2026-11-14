# t1ha

The t1ha (Fast Positive Hash) family of fast, non-cryptographic hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-t1ha:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## t1ha0-32le

t1ha0, the 32-bit little-endian variant, with output size of 64 bits using `seed`.

```kotlin
val hash: ByteArray = T1ha.t1ha0_32le().hash("Hello, world!")
val customHash: ByteArray = T1ha.t1ha0_32le(seed = 1u).hash("Hello, world!")
```

## t1ha1-le

t1ha1, the little-endian variant, with output size of 64 bits using `seed`.

```kotlin
val hash: ByteArray = T1ha.t1ha1Le().hash("Hello, world!")
val customHash: ByteArray = T1ha.t1ha1Le(seed = 1u).hash("Hello, world!")
```

## t1ha2-atonce

t1ha2, hashing its whole input at once, with output size of 64 bits using `seed`.

```kotlin
val hash: ByteArray = T1ha.t1ha2AtOnce().hash("Hello, world!")
val customHash: ByteArray = T1ha.t1ha2AtOnce(seed = 1u).hash("Hello, world!")
```

## t1ha2-atonce128

t1ha2, hashing its whole input at once, with output size of 128 bits using `seed`.

```kotlin
val hash: ByteArray = T1ha.t1ha2AtOnce128().hash("Hello, world!")
val customHash: ByteArray = T1ha.t1ha2AtOnce128(seed = 1u).hash("Hello, world!")
```

## t1ha2-stream

t1ha2, hashing its input incrementally, with output size of 64 bits using the seeds `seedX` and `seedY`.

```kotlin
val hash: ByteArray = T1ha.t1ha2Stream().hash("Hello, world!")
val customHash: ByteArray = T1ha.t1ha2Stream(seedX = 1u, seedY = 2u).hash("Hello, world!")
```

## t1ha2-stream128

t1ha2, hashing its input incrementally, with output size of 128 bits using the seeds `seedX` and `seedY`.

```kotlin
val hash: ByteArray = T1ha.t1ha2Stream128().hash("Hello, world!")
val customHash: ByteArray = T1ha.t1ha2Stream128(seedX = 1u, seedY = 2u).hash("Hello, world!")
```
