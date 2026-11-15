# rapidhash

The rapidhash fast, non-cryptographic hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-rapidhash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## rapidhash

rapidhash V3.

```kotlin
val hash: ByteArray = Rapidhash.rapidhash().hash("Hello, world!")
val customHash: ByteArray = Rapidhash.rapidhash(seed = 1u).hash("Hello, world!")
```

## rapidhashMicro

rapidhashMicro, the rapidhash V3 variant tuned for smaller code size.

```kotlin
val hash: ByteArray = Rapidhash.rapidhashMicro().hash("Hello, world!")
val customHash: ByteArray = Rapidhash.rapidhashMicro(seed = 1u).hash("Hello, world!")
```

## rapidhashNano

rapidhashNano, the rapidhash V3 variant tuned for the smallest code size.

```kotlin
val hash: ByteArray = Rapidhash.rapidhashNano().hash("Hello, world!")
val customHash: ByteArray = Rapidhash.rapidhashNano(seed = 1u).hash("Hello, world!")
```
