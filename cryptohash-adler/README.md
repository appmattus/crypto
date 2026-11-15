# Adler

The Adler-32 checksum, as used by zlib.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-adler:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## Adler32

[Adler-32](https://www.rfc-editor.org/rfc/rfc1950#section-9), the checksum zlib uses, producing a 4-byte big-endian value.

```kotlin
val hash: ByteArray = Adler.adler32.hash("Hello, world!")
```
