# MD

The MD2, MD4 and MD5 hashes. All three are broken, so only use them for compatibility.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-md:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## MD2

MD2, with output size of 128 bits, which also supports HMAC. It is broken, so only use it for compatibility.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Md.md2.hash("Hello, world!")
val mac: ByteArray = Md.md2.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## MD4

MD4, with output size of 128 bits, which also supports HMAC. It is broken, so only use it for compatibility.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Md.md4.hash("Hello, world!")
val mac: ByteArray = Md.md4.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## MD5

MD5, with output size of 128 bits, which also supports HMAC. It is broken, so only use it for compatibility.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Md.md5.hash("Hello, world!")
val mac: ByteArray = Md.md5.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
