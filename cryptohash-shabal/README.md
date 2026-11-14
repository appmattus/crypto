# Shabal

The Shabal family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-shabal:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Shabal-192

Shabal with output size of 192 bits.

```kotlin
val hash: ByteArray = Shabal.shabal192.hash("Hello, world!")
```

## Shabal-224

Shabal with output size of 224 bits.

```kotlin
val hash: ByteArray = Shabal.shabal224.hash("Hello, world!")
```

## Shabal-256

Shabal with output size of 256 bits.

```kotlin
val hash: ByteArray = Shabal.shabal256.hash("Hello, world!")
```

## Shabal-384

Shabal with output size of 384 bits.

```kotlin
val hash: ByteArray = Shabal.shabal384.hash("Hello, world!")
```

## Shabal-512

Shabal with output size of 512 bits.

```kotlin
val hash: ByteArray = Shabal.shabal512.hash("Hello, world!")
```
