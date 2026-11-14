# SIMD

The SIMD family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-simd:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## SIMD-224

SIMD with output size of 224 bits.

```kotlin
val hash: ByteArray = Simd.simd224.hash("Hello, world!")
```

## SIMD-256

SIMD with output size of 256 bits.

```kotlin
val hash: ByteArray = Simd.simd256.hash("Hello, world!")
```

## SIMD-384

SIMD with output size of 384 bits.

```kotlin
val hash: ByteArray = Simd.simd384.hash("Hello, world!")
```

## SIMD-512

SIMD with output size of 512 bits.

```kotlin
val hash: ByteArray = Simd.simd512.hash("Hello, world!")
```
