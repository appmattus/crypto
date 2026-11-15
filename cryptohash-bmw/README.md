# Blue Midnight Wish

The Blue Midnight Wish family of hashes, a SHA-3 competition candidate.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-bmw:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## BMW-224

Blue Midnight Wish with output size of 224 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Bmw.bmw224.hash("Hello, world!")
val mac: ByteArray = Bmw.bmw224.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## BMW-256

Blue Midnight Wish with output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Bmw.bmw256.hash("Hello, world!")
val mac: ByteArray = Bmw.bmw256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## BMW-384

Blue Midnight Wish with output size of 384 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Bmw.bmw384.hash("Hello, world!")
val mac: ByteArray = Bmw.bmw384.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## BMW-512

Blue Midnight Wish with output size of 512 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Bmw.bmw512.hash("Hello, world!")
val mac: ByteArray = Bmw.bmw512.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
