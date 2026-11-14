# RIPEMD

The original RIPEMD hash and the strengthened RIPEMD-128, -160, -256 and -320.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-ripemd:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## RIPEMD

The original RIPEMD, with output size of 128 bits. It is broken, and isn't the strengthened `ripeMd128`.

```kotlin
val hash: ByteArray = RipeMd.ripeMd.hash("Hello, world!")
```

## RIPEMD-128

The strengthened RIPEMD-128, with output size of 128 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = RipeMd.ripeMd128.hash("Hello, world!")
val mac: ByteArray = RipeMd.ripeMd128.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## RIPEMD-160

The strengthened RIPEMD-160, with output size of 160 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = RipeMd.ripeMd160.hash("Hello, world!")
val mac: ByteArray = RipeMd.ripeMd160.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## RIPEMD-256

The strengthened RIPEMD-256, with output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = RipeMd.ripeMd256.hash("Hello, world!")
val mac: ByteArray = RipeMd.ripeMd256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## RIPEMD-320

The strengthened RIPEMD-320, with output size of 320 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = RipeMd.ripeMd320.hash("Hello, world!")
val mac: ByteArray = RipeMd.ripeMd320.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
