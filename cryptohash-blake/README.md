# BLAKE

The BLAKE family of hashes, a SHA-3 competition finalist.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-blake:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## BLAKE-224

BLAKE with output size of 224 bits.

```kotlin
val hash: ByteArray = Blake.blake224.hash("Hello, world!")
```

## BLAKE-256

BLAKE with output size of 256 bits.

```kotlin
val hash: ByteArray = Blake.blake256.hash("Hello, world!")
```

## BLAKE-384

BLAKE with output size of 384 bits.

```kotlin
val hash: ByteArray = Blake.blake384.hash("Hello, world!")
```

## BLAKE-512

BLAKE with output size of 512 bits.

```kotlin
val hash: ByteArray = Blake.blake512.hash("Hello, world!")
```
