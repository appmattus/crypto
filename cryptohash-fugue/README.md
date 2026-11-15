# Fugue

The Fugue family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-fugue:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Fugue-224

Fugue with output size of 224 bits.

```kotlin
val hash: ByteArray = Fugue.fugue224.hash("Hello, world!")
```

## Fugue-256

Fugue with output size of 256 bits.

```kotlin
val hash: ByteArray = Fugue.fugue256.hash("Hello, world!")
```

## Fugue-384

Fugue with output size of 384 bits.

```kotlin
val hash: ByteArray = Fugue.fugue384.hash("Hello, world!")
```

## Fugue-512

Fugue with output size of 512 bits.

```kotlin
val hash: ByteArray = Fugue.fugue512.hash("Hello, world!")
```
