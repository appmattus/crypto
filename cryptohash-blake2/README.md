# BLAKE2

The BLAKE2b and BLAKE2s hashes of RFC 7693, with optional key, salt and personalisation.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-blake2:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Blake2b

BLAKE2b with output size of `outputSizeBits` bits (default: 512 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a multiple of 8 between 8 and 512.

```kotlin
val hash: ByteArray = Blake2.blake2b().hash("Hello, world!")
val customHash: ByteArray = Blake2.blake2b(outputSizeBits = 256).hash("Hello, world!")
```

## Blake2b keyed

BLAKE2b tuned to your specific requirements, such as `key`ed hashing, hashing with a `salt`, or `personalisation`, or any combination thereof, with output size of `outputSizeBits` bits (default: 512 bits). An empty key means unkeyed hashing. The arrays are copied. Throws `IllegalArgumentException` if `key` is longer than 64 bytes, `salt` or `personalisation` isn't 16 bytes, or `outputSizeBits` isn't a multiple of 8 between 8 and 512.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Blake2.blake2bKeyed(
    key = key,
    salt = "saltsaltsaltsalt".encodeToByteArray(),
    personalisation = "MyAppPersonalise".encodeToByteArray(),
    outputSizeBits = 256
).hash("Hello, world!")
```

## Blake2s

BLAKE2s with output size of `outputSizeBits` bits (default: 256 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a multiple of 8 between 8 and 256.

```kotlin
val hash: ByteArray = Blake2.blake2s().hash("Hello, world!")
val customHash: ByteArray = Blake2.blake2s(outputSizeBits = 128).hash("Hello, world!")
```

## Blake2s keyed

BLAKE2s tuned to your specific requirements, such as `key`ed hashing, hashing with a `salt`, or `personalisation`, or any combination thereof, with output size of `outputSizeBits` bits (default: 256 bits). An empty key means unkeyed hashing. The arrays are copied. Throws `IllegalArgumentException` if `key` is longer than 32 bytes, `salt` or `personalisation` isn't 8 bytes, or `outputSizeBits` isn't a multiple of 8 between 8 and 256.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Blake2.blake2sKeyed(
    key = key,
    salt = "saltsalt".encodeToByteArray(),
    personalisation = "MyAppPer".encodeToByteArray(),
    outputSizeBits = 128
).hash("Hello, world!")
```
