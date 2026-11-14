# Keccak family

Keccak and the standards built on it: SHA-3, SHAKE, the SP 800-185 functions and KangarooTwelve.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-keccak:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Keccak

### Keccak-224

Keccak with output size of 224 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Keccak.keccak224.hash("Hello, world!")
val mac: ByteArray = Keccak.keccak224.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### Keccak-256

Keccak with output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Keccak.keccak256.hash("Hello, world!")
val mac: ByteArray = Keccak.keccak256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### Keccak-288

Keccak with output size of 288 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Keccak.keccak288.hash("Hello, world!")
val mac: ByteArray = Keccak.keccak288.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### Keccak-384

Keccak with output size of 384 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Keccak.keccak384.hash("Hello, world!")
val mac: ByteArray = Keccak.keccak384.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### Keccak-512

Keccak with output size of 512 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Keccak.keccak512.hash("Hello, world!")
val mac: ByteArray = Keccak.keccak512.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## SHA-3

### SHA3-224

SHA3-224, with output size of 224 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha3.sha3_224.hash("Hello, world!")
val mac: ByteArray = Sha3.sha3_224.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### SHA3-256

SHA3-256, with output size of 256 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha3.sha3_256.hash("Hello, world!")
val mac: ByteArray = Sha3.sha3_256.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### SHA3-384

SHA3-384, with output size of 384 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha3.sha3_384.hash("Hello, world!")
val mac: ByteArray = Sha3.sha3_384.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### SHA3-512

SHA3-512, with output size of 512 bits, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha3.sha3_512.hash("Hello, world!")
val mac: ByteArray = Sha3.sha3_512.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

### SHAKE128

SHAKE128, with output size of 256 bits.

```kotlin
val hash: ByteArray = Sha3.shake128.hash("Hello, world!")
```

### SHAKE256

SHAKE256, with output size of 512 bits.

```kotlin
val hash: ByteArray = Sha3.shake256.hash("Hello, world!")
```

## SP 800-185

### cSHAKE128

cSHAKE128, with output size of 256 bits, using a `customisation` string and a `functionName`.

```kotlin
val hash: ByteArray = Sp800185.cshake128().hash("Hello, world!")
val customHash: ByteArray = Sp800185.cshake128(
    customisation = "My App".encodeToByteArray()
).hash("Hello, world!")
```

### cSHAKE256

cSHAKE256, with output size of 512 bits, using a `customisation` string and a `functionName`.

```kotlin
val hash: ByteArray = Sp800185.cshake256().hash("Hello, world!")
val customHash: ByteArray = Sp800185.cshake256(
    customisation = "My App".encodeToByteArray()
).hash("Hello, world!")
```

### KMAC128

KMAC128, a keyed MAC using `key` and a `customisation` string, with output size of `outputSizeBits` bits (default: 256 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sp800185.kmac128(
    key = key,
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 512
).hash("Hello, world!")
```

### KMAC256

KMAC256, a keyed MAC using `key` and a `customisation` string, with output size of `outputSizeBits` bits (default: 512 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sp800185.kmac256(
    key = key,
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 1024
).hash("Hello, world!")
```

### TupleHash128

TupleHash128, which hashes each update as one element of a tuple, using a `customisation` string, with output size of `outputSizeBits` bits (default: 256 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = Sp800185.tupleHash128().hash("Hello, world!")
val customHash: ByteArray = Sp800185.tupleHash128(
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 512
).hash("Hello, world!")
```

### TupleHash256

TupleHash256, which hashes each update as one element of a tuple, using a `customisation` string, with output size of `outputSizeBits` bits (default: 512 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = Sp800185.tupleHash256().hash("Hello, world!")
val customHash: ByteArray = Sp800185.tupleHash256(
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 1024
).hash("Hello, world!")
```

### ParallelHash128

ParallelHash128, which hashes its input in blocks of `blockSize` bytes, using a `customisation` string, with output size of `outputSizeBits` bits (default: 256 bits). Throws `IllegalArgumentException` if `blockSize` isn't positive, or `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = Sp800185.parallelHash128(
    blockSize = 8192,
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 512
).hash("Hello, world!")
```

### ParallelHash256

ParallelHash256, which hashes its input in blocks of `blockSize` bytes, using a `customisation` string, with output size of `outputSizeBits` bits (default: 512 bits). Throws `IllegalArgumentException` if `blockSize` isn't positive, or `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = Sp800185.parallelHash256(
    blockSize = 8192,
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 1024
).hash("Hello, world!")
```

## KangarooTwelve

### KT128

KT128, using a `customisation` string, with output size of `outputSizeBits` bits (default: 256 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = KangarooTwelve.kt128().hash("Hello, world!")
val customHash: ByteArray = KangarooTwelve.kt128(
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 512
).hash("Hello, world!")
```

### KT256

KT256, using a `customisation` string, with output size of `outputSizeBits` bits (default: 512 bits). Throws `IllegalArgumentException` if `outputSizeBits` isn't a positive multiple of 8.

```kotlin
val hash: ByteArray = KangarooTwelve.kt256().hash("Hello, world!")
val customHash: ByteArray = KangarooTwelve.kt256(
    customisation = "My App".encodeToByteArray(),
    outputSizeBits = 1024
).hash("Hello, world!")
```
