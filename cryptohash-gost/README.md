# GOST R 34.11-94

The GOST R 34.11-94 hash, with the CryptoPro parameters.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-gost:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## GOST3411-94

GOST R 34.11-94, with output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Gost.gost3411_94.hash("Hello, world!")
val mac: ByteArray = Gost.gost3411_94.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
