# ECHO

The ECHO family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-echo:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## ECHO-224

ECHO with output size of 224 bits.

```kotlin
val hash: ByteArray = Echo.echo224.hash("Hello, world!")
```

## ECHO-256

ECHO with output size of 256 bits.

```kotlin
val hash: ByteArray = Echo.echo256.hash("Hello, world!")
```

## ECHO-384

ECHO with output size of 384 bits.

```kotlin
val hash: ByteArray = Echo.echo384.hash("Hello, world!")
```

## ECHO-512

ECHO with output size of 512 bits.

```kotlin
val hash: ByteArray = Echo.echo512.hash("Hello, world!")
```
