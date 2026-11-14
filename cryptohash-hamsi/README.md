# Hamsi

The Hamsi family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-hamsi:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Hamsi-224

Hamsi with output size of 224 bits.

```kotlin
val hash: ByteArray = Hamsi.hamsi224.hash("Hello, world!")
```

## Hamsi-256

Hamsi with output size of 256 bits.

```kotlin
val hash: ByteArray = Hamsi.hamsi256.hash("Hello, world!")
```

## Hamsi-384

Hamsi with output size of 384 bits.

```kotlin
val hash: ByteArray = Hamsi.hamsi384.hash("Hello, world!")
```

## Hamsi-512

Hamsi with output size of 512 bits.

```kotlin
val hash: ByteArray = Hamsi.hamsi512.hash("Hello, world!")
```
