# wyhash

The wyhash fast, non-cryptographic hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-wyhash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## wyhash

wyhash with output size of 64 bits. Throws `IllegalArgumentException` if `secret` has fewer than four values.

```kotlin
val hash: ByteArray = Wyhash.wyhash64().hash("Hello, world!")
val customHash: ByteArray = Wyhash.wyhash64(
    seed = 1u,
    secret = Wyhash.makeSecret(42u),
    extraProtection = true
).hash("Hello, world!")
```

## wyhash32

wyhash with output size of 32 bits.

```kotlin
val hash: ByteArray = Wyhash.wyhash32().hash("Hello, world!")
val customHash: ByteArray = Wyhash.wyhash32(seed = 1u).hash("Hello, world!")
```
