# RadioGatún

The RadioGatún hashes, with 32-bit or 64-bit words.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-radiogatun:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## RadioGatun32

RadioGatún`32`, with 32-bit words and output size of 256 bits.

```kotlin
val hash: ByteArray = RadioGatun.radioGatun32.hash("Hello, world!")
```

## RadioGatun64

RadioGatún`64`, with 64-bit words and output size of 256 bits.

```kotlin
val hash: ByteArray = RadioGatun.radioGatun64.hash("Hello, world!")
```
