# MetroHash

The MetroHash fast, non-cryptographic hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-metrohash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## MetroHash64

MetroHash with output size of 64 bits.

```kotlin
val hash: ByteArray = MetroHash.metroHash64().hash("Hello, world!")
val customHash: ByteArray = MetroHash.metroHash64(seed = 1u).hash("Hello, world!")
```

## MetroHash128

MetroHash with output size of 128 bits.

```kotlin
val hash: ByteArray = MetroHash.metroHash128().hash("Hello, world!")
val customHash: ByteArray = MetroHash.metroHash128(seed = 1u).hash("Hello, world!")
```
