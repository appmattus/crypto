# Kupyna

The Kupyna family of hashes, the Ukrainian standard DSTU 7564:2014.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-kupyna:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Kupyna-256

Kupyna with output size of 256 bits.

```kotlin
val hash: ByteArray = Kupyna.kupyna256.hash("Hello, world!")
```

## Kupyna-384

Kupyna with output size of 384 bits.

```kotlin
val hash: ByteArray = Kupyna.kupyna384.hash("Hello, world!")
```

## Kupyna-512

Kupyna with output size of 512 bits.

```kotlin
val hash: ByteArray = Kupyna.kupyna512.hash("Hello, world!")
```
