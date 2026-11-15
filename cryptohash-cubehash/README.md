# CubeHash

The CubeHash family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-cubehash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## CubeHash-224

CubeHash with output size of 224 bits.

```kotlin
val hash: ByteArray = CubeHash.cubeHash224.hash("Hello, world!")
```

## CubeHash-256

CubeHash with output size of 256 bits.

```kotlin
val hash: ByteArray = CubeHash.cubeHash256.hash("Hello, world!")
```

## CubeHash-384

CubeHash with output size of 384 bits.

```kotlin
val hash: ByteArray = CubeHash.cubeHash384.hash("Hello, world!")
```

## CubeHash-512

CubeHash with output size of 512 bits.

```kotlin
val hash: ByteArray = CubeHash.cubeHash512.hash("Hello, world!")
```
