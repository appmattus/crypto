# SHAvite-3

The SHAvite-3 family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-shavite:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## SHAvite-224

SHAvite-3 with output size of 224 bits.

```kotlin
val hash: ByteArray = Shavite.shavite224.hash("Hello, world!")
```

## SHAvite-256

SHAvite-3 with output size of 256 bits.

```kotlin
val hash: ByteArray = Shavite.shavite256.hash("Hello, world!")
```

## SHAvite-384

SHAvite-3 with output size of 384 bits.

```kotlin
val hash: ByteArray = Shavite.shavite384.hash("Hello, world!")
```

## SHAvite-512

SHAvite-3 with output size of 512 bits.

```kotlin
val hash: ByteArray = Shavite.shavite512.hash("Hello, world!")
```
