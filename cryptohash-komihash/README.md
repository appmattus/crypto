# komihash

The komihash fast, non-cryptographic hash.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-komihash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## komihash

komihash version 5.

```kotlin
val hash: ByteArray = Komihash.komihash().hash("Hello, world!")
val customHash: ByteArray = Komihash.komihash(seed = 1u).hash("Hello, world!")
```
