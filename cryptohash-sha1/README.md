# SHA-1

The SHA-0 and SHA-1 hashes. Both are broken, so only use them for compatibility.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-sha1:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## SHA-0

SHA-0, with output size of 160 bits, which also supports HMAC It is broken, so only use it for compatibility.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha1.sha0.hash("Hello, world!")
val mac: ByteArray = Sha1.sha0.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## SHA-1

SHA-1, with output size of 160 bits, which also supports HMAC. The platform's own implementation is used where it has one. It is broken, so only use it for compatibility.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Sha1.sha1.hash("Hello, world!")
val mac: ByteArray = Sha1.sha1.newHmac(key).digest("Hello, world!".encodeToByteArray())
```
