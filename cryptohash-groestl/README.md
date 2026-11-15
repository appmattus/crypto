# Grøstl

The Grøstl family of hashes, a SHA-3 competition finalist.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-groestl:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Groestl-224

Grøstl with output size of 224 bits.

```kotlin
val hash: ByteArray = Groestl.groestl224.hash("Hello, world!")
```

## Groestl-256

Grøstl with output size of 256 bits.

```kotlin
val hash: ByteArray = Groestl.groestl256.hash("Hello, world!")
```

## Groestl-384

Grøstl with output size of 384 bits.

```kotlin
val hash: ByteArray = Groestl.groestl384.hash("Hello, world!")
```

## Groestl-512

Grøstl with output size of 512 bits.

```kotlin
val hash: ByteArray = Groestl.groestl512.hash("Hello, world!")
```
