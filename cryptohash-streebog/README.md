# Streebog

The Streebog hashes, the Russian standard GOST R 34.11-2012.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-streebog:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Streebog-256

Streebog with output size of 256 bits, GOST R 34.11-2012 256, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Streebog.streebog256.hash("Hello, world!")
val mac: ByteArray = Streebog.streebog256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Streebog-512

Streebog with output size of 512 bits, GOST R 34.11-2012 512, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Streebog.streebog512.hash("Hello, world!")
val mac: ByteArray = Streebog.streebog512.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
