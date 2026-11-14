# Skein

The Skein family of hashes, a SHA-3 competition finalist, with its MAC mode.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-skein:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Skein-256-128

Skein with internal state of 256 bits and output size of 128 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein256_128.hash("Hello, world!")
val mac: ByteArray = Skein.skein256_128.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-256-160

Skein with internal state of 256 bits and output size of 160 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein256_160.hash("Hello, world!")
val mac: ByteArray = Skein.skein256_160.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-256-224

Skein with internal state of 256 bits and output size of 224 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein256_224.hash("Hello, world!")
val mac: ByteArray = Skein.skein256_224.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-256-256

Skein with internal state of 256 bits and output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein256_256.hash("Hello, world!")
val mac: ByteArray = Skein.skein256_256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-512-128

Skein with internal state of 512 bits and output size of 128 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein512_128.hash("Hello, world!")
val mac: ByteArray = Skein.skein512_128.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-512-160

Skein with internal state of 512 bits and output size of 160 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein512_160.hash("Hello, world!")
val mac: ByteArray = Skein.skein512_160.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-512-224

Skein with internal state of 512 bits and output size of 224 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein512_224.hash("Hello, world!")
val mac: ByteArray = Skein.skein512_224.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-512-256

Skein with internal state of 512 bits and output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein512_256.hash("Hello, world!")
val mac: ByteArray = Skein.skein512_256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-512-384

Skein with internal state of 512 bits and output size of 384 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein512_384.hash("Hello, world!")
val mac: ByteArray = Skein.skein512_384.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-512-512

Skein with internal state of 512 bits and output size of 512 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein512_512.hash("Hello, world!")
val mac: ByteArray = Skein.skein512_512.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-1024-384

Skein with internal state of 1024 bits and output size of 384 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein1024_384.hash("Hello, world!")
val mac: ByteArray = Skein.skein1024_384.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-1024-512

Skein with internal state of 1024 bits and output size of 512 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein1024_512.hash("Hello, world!")
val mac: ByteArray = Skein.skein1024_512.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein-1024-1024

Skein with internal state of 1024 bits and output size of 1024 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Skein.skein1024_1024.hash("Hello, world!")
val mac: ByteArray = Skein.skein1024_1024.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Skein with any sizes

Skein with internal state of `blockSizeBits` bits and output size of `outputSizeBits` bits. Throws `IllegalArgumentException` if `blockSizeBits` isn't 256, 512 or 1024, or `outputSizeBits` isn't 128, 160, 224, 256, 384, 512 or 1024.

```kotlin
val hash: ByteArray = Skein.skein(blockSizeBits = 512, outputSizeBits = 256).hash("Hello, world!")
```

## Skein MAC

Skein MAC, using `key`, with internal state of `blockSizeBits` bits and output size of `outputSizeBits` bits. An empty key means unkeyed hashing. The key is copied. Throws `IllegalArgumentException` if `blockSizeBits` isn't 256, 512 or 1024, `outputSizeBits` isn't 128, 160, 224, 256, 384, 512 or 1024, or `key` is neither empty nor at least 16 bytes.

```kotlin
val key = "0123456789abcdef".encodeToByteArray() // 16 bytes

val hash: ByteArray = Skein.skeinKeyed(
    blockSizeBits = 512,
    outputSizeBits = 256,
    key = key
).hash("Hello, world!")
```
