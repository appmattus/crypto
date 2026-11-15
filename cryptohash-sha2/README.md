# SHA-2

The SHA-2 family of hashes of FIPS 180-4. The platform's own implementation is used where it has one.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-sha2:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## SHA-224

SHA-224, with output size of 224 bits, which also supports HMAC. The platform's own implementation is used where it has one.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha2.sha224.hash("Hello, world!")
val mac: ByteArray = Sha2.sha224.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## SHA-256

SHA-256, with output size of 256 bits, which also supports HMAC. The platform's own implementation is used where it has one.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha2.sha256.hash("Hello, world!")
val mac: ByteArray = Sha2.sha256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## SHA-384

SHA-384, with output size of 384 bits, which also supports HMAC. The platform's own implementation is used where it has one.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha2.sha384.hash("Hello, world!")
val mac: ByteArray = Sha2.sha384.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## SHA-512

SHA-512, with output size of 512 bits, which also supports HMAC. The platform's own implementation is used where it has one.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha2.sha512.hash("Hello, world!")
val mac: ByteArray = Sha2.sha512.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## SHA-512/224

SHA-512/224, with output size of 224 bits, which also supports HMAC. The platform's own implementation is used where it has one.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha2.sha512_224.hash("Hello, world!")
val mac: ByteArray = Sha2.sha512_224.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## SHA-512/256

SHA-512/256, with output size of 256 bits, which also supports HMAC. The platform's own implementation is used where it has one.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha2.sha512_256.hash("Hello, world!")
val mac: ByteArray = Sha2.sha512_256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
