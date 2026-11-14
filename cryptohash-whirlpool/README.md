# Whirlpool

The Whirlpool hash and its two earlier versions.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-whirlpool:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Whirlpool

Whirlpool, the current (2003) variant, with output size of 512 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Whirlpool.whirlpool.hash("Hello, world!")
val mac: ByteArray = Whirlpool.whirlpool.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Whirlpool-0

Whirlpool-0, the first (2000) variant, with output size of 512 bits.

```kotlin
val hash: ByteArray = Whirlpool.whirlpool0.hash("Hello, world!")
```

## Whirlpool-T

Whirlpool-T, the second (2001) variant, with output size of 512 bits.

```kotlin
val hash: ByteArray = Whirlpool.whirlpoolT.hash("Hello, world!")
```
