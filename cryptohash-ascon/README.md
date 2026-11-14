# Ascon

The Ascon hash and extendable-output functions of NIST SP 800-232.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-ascon:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Ascon-Hash256

Ascon-Hash256, with output size of 256 bits.

```kotlin
val hash: ByteArray = Ascon.hash256.hash("Hello, world!")
```

## Ascon-XOF128

Ascon-XOF128, with output size of `outputSizeBits` bits. Throws `IllegalArgumentException` if `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = Ascon.xof128().hash("Hello, world!")
val customHash: ByteArray = Ascon.xof128(outputSizeBits = 512).hash("Hello, world!")
```

## Ascon-CXOF128

Ascon-CXOF128, the customisable variant of `xof128`, with a `customisation` string of at most 256 bytes and output size of `outputSizeBits` bits. The customisation string is copied. Throws `IllegalArgumentException` if `customisation` is longer than 256 bytes, or `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = Ascon.cxof128().hash("Hello, world!")
val customHash: ByteArray = Ascon.cxof128(
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 512
).hash("Hello, world!")
```
