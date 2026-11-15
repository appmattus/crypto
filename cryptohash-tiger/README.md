# Tiger

The Tiger and Tiger2 hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-tiger:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Tiger

Tiger, which also supports HMAC.

```kotlin
val key = "my secret key".encodeToByteArray()

val hash: ByteArray = Tiger.tiger.hash("Hello, world!")
val mac: ByteArray = Tiger.tiger.newHmac(key).digest("Hello, world!".encodeToByteArray())
```

## Tiger2

Tiger2, which differs from Tiger only in its padding.

```kotlin
val hash: ByteArray = Tiger.tiger2.hash("Hello, world!")
```
