# SM3

The Chinese standard SM3 hash.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-sm3:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## SM3

SM3, with output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sm3.sm3.hash("Hello, world!")
val mac: ByteArray = Sm3.sm3.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
