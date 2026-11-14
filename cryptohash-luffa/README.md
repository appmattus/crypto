# Luffa

The Luffa family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-luffa:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Luffa-224

Luffa with output size of 224 bits.

```kotlin
val hash: ByteArray = Luffa.luffa224.hash("Hello, world!")
```

## Luffa-256

Luffa with output size of 256 bits.

```kotlin
val hash: ByteArray = Luffa.luffa256.hash("Hello, world!")
```

## Luffa-384

Luffa with output size of 384 bits.

```kotlin
val hash: ByteArray = Luffa.luffa384.hash("Hello, world!")
```

## Luffa-512

Luffa with output size of 512 bits.

```kotlin
val hash: ByteArray = Luffa.luffa512.hash("Hello, world!")
```
