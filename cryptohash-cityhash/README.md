# CityHash and FarmHash

Google's CityHash and FarmHash families of fast, non-cryptographic hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-cityhash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## CityHash

### CityHash32

CityHash32, with output size of 32 bits.

```kotlin
val hash: ByteArray = CityHash.cityHash32.hash("Hello, world!")
```

### CityHash64

CityHash64, with output size of 64 bits.

```kotlin
val hash: ByteArray = CityHash.cityHash64().hash("Hello, world!")
val hashWithSeed: ByteArray = CityHash.cityHash64(seed = 1u).hash("Hello, world!")
val hashWithSeeds: ByteArray = CityHash.cityHash64(seed1 = 1u, seed2 = 2u).hash("Hello, world!")
```

### CityHash128

CityHash128, with output size of 128 bits.

```kotlin
val hash: ByteArray = CityHash.cityHash128().hash("Hello, world!")
val hashWithSeeds: ByteArray = CityHash.cityHash128(seedLow = 1u, seedHigh = 2u).hash("Hello, world!")
```

### CityHashCrc128

CityHashCrc128, with output size of 128 bits.

```kotlin
val hash: ByteArray = CityHash.cityHashCrc128().hash("Hello, world!")
val hashWithSeeds: ByteArray = CityHash.cityHashCrc128(seedLow = 1u, seedHigh = 2u).hash("Hello, world!")
```

### CityHashCrc256

CityHashCrc256, with output size of 256 bits.

```kotlin
val hash: ByteArray = CityHash.cityHashCrc256.hash("Hello, world!")
```

## FarmHash

### FarmHash32

FarmHash32, with output size of 32 bits.

```kotlin
val hash: ByteArray = FarmHash.farmHash32().hash("Hello, world!")
val hashWithSeed: ByteArray = FarmHash.farmHash32(seed = 1u).hash("Hello, world!")
```

### FarmHash64

FarmHash64, with output size of 64 bits.

```kotlin
val hash: ByteArray = FarmHash.farmHash64().hash("Hello, world!")
val hashWithSeed: ByteArray = FarmHash.farmHash64(seed = 1u).hash("Hello, world!")
val hashWithSeeds: ByteArray = FarmHash.farmHash64(seed1 = 1u, seed2 = 2u).hash("Hello, world!")
```

### FarmHash128

FarmHash128, with output size of 128 bits.

```kotlin
val hash: ByteArray = FarmHash.farmHash128().hash("Hello, world!")
val hashWithSeeds: ByteArray = FarmHash.farmHash128(seedLow = 1u, seedHigh = 2u).hash("Hello, world!")
```
