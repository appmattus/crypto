# MurmurHash

The MurmurHash family of fast, non-cryptographic hashes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-murmurhash:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## MurmurHash1

[MurmurHash1](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp) for x86 platform with output size of 32 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash1().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash1(seed = 1u).hash("Hello, world!")
```

## MurmurHash2

[MurmurHash2](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x86 platform with output size of 32 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash2().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash2(seed = 1u).hash("Hello, world!")
```

## MurmurHash2A

[MurmurHash2A](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp), the incremental variant of MurmurHash2, for x86 platform with output size of 32 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash2A().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash2A(seed = 1u).hash("Hello, world!")
```

## MurmurHash64A

[MurmurHash64A](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x64 platform with output size of 64 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash64A().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash64A(seed = 1u).hash("Hello, world!")
```

## MurmurHash64B

[MurmurHash64B](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x86 platform with output size of 64 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash64B().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash64B(seed = 1u).hash("Hello, world!")
```

## MurmurHash3-x86-32

[MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x86 platform with output size of 32 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash3X86_32().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash3X86_32(seed = 1u).hash("Hello, world!")
```

## MurmurHash3-x86-128

[MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x86 platform with output size of 128 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash3X86_128().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash3X86_128(seed = 1u).hash("Hello, world!")
```

## MurmurHash3-x64-128

[MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x64 platform with output size of 128 bits.

```kotlin
val hash: ByteArray = MurmurHash.murmurHash3X64_128().hash("Hello, world!")
val customHash: ByteArray = MurmurHash.murmurHash3X64_128(seed = 1u).hash("Hello, world!")
```
