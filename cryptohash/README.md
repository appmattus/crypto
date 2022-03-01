# cryptohash

A Kotlin Multiplatform Mobile library to provide a set of cryptographic (and
not so cryptographic) hashing functions.

The following algorithms are supported:

## Cyclic redundancy checks

- CRC32, CRC32B, CRC32C

## Checksums

- Adler32

## Non-cryptographic hash functions

- CityHash32, CityHash64, CityHash128, CityHashCrc128, CityHashCrc256
- FarmHash32, FarmHash64, FarmHash128
- HighwayHash-64, HighwayHash-128, HighwayHash-256
- MetroHash64, MetroHash128
- MurmurHash1
- MurmurHash2, MurmurHash64A, MurmurHash64B, MurmurHash2A (aka CMurmurHash2A)
- MurmurHash3-x86-32, MurmurHash3-x86-128, MurmurHash3-x64-128
- t1ha0-32le
- t1ha1-le
- t1ha2-atonce, t1ha2-atonce128, t1ha2-stream, t1ha2-stream128
- xxHash-32, xxHash-64
- xxHash3-64, xxHash3-128

## Keyed cryptographic hash functions

- Blake2b, Blake2s
- Blake3
- HMAC
- Skein

## Unkeyed cryptographic hash functions

- BLAKE-224, BLAKE-256, BLAKE-384, BLAKE-512
- Blake2b-160, Blake2b-256, Blake2b-384, Blake2b-512, Blake2s-128, Blake2s-160,
  Blake2s-224, Blake2s-256
- Blake3
- BMW-224, BMW-256, BMW-384, BMW-512
- cSHAKE
- CubeHash-224, CubeHash-256, CubeHash-384, CubeHash-512
- ECHO-224, ECHO-256, ECHO-384, ECHO-512
- Fugue-224, Fugue-256, Fugue-384, Fugue-512
- GOST3411-94, GOST3411-2012-256, GOST3411-2012-512
- Groestl-224, Groestl-256, Groestl-384, Groestl-512
- Hamsi-224, Hamsi-256, Hamsi-384, Hamsi-512
- Haraka-256, Haraka-512
- HAVAL-128-3, HAVAL-128-4, HAVAL-128-5, HAVAL-160-3, HAVAL-160-4, HAVAL-160-5,
  HAVAL-192-3, HAVAL-192-4, HAVAL-192-5, HAVAL-224-3, HAVAL-224-4, HAVAL-224-5,
  HAVAL-256-3, HAVAL-256-4, HAVAL-256-5
- JH-224, JH-256, JH-384, JH-512
- Keccak-224, Keccak-256, Keccak-288, Keccak-384, Keccak-512
- Kupyna-256 (aka DSTU7564-256), Kupyna-384 (aka DSTU7564-384), Kupyna-512 (aka
  DSTU7564-512)
- Luffa-224, Luffa-256, Luffa-384, Luffa-512
- MD2, MD4, MD5
- PANAMA
- RadioGatun32, RadioGatun64
- RIPEMD, RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320
- SHA-0, SHA-1, SHA-224, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- Shabal-192, Shabal-224, Shabal-256, Shabal-384, Shabal-512
- SHAKE128, SHAKE256
- SHAvite-224, SHAvite-256, SHAvite-384, SHAvite-512
- SIMD-224, SIMD-256, SIMD-384, SIMD-512
- Skein-256-128, Skein-256-160, Skein-256-224, Skein-256-256, Skein-512-128,
  Skein-512-160, Skein-512-224, Skein-512-256, Skein-512-384, Skein-512-512,
  Skein-1024-384, Skein-1024-512, Skein-1024-1024
- SM3
- Tiger, Tiger2
- Whirlpool, Whirlpool-0, Whirlpool-T

## Getting started

![badge][badge-android]
![badge][badge-ios]
![badge][badge-watchos]
![badge][badge-tvos]
![badge][badge-mac]
![badge][badge-linux]
![badge][badge-windows]
![badge][badge-jvm]
[![Maven Central](https://img.shields.io/maven-central/v/com.appmattus.crypto/cryptohash)](https://search.maven.org/search?q=g:com.appmattus.crypto)

Include the following dependency in your *build.gradle.kts* file:

```kotlin
commonMain {
    implementation("com.appmattus.crypto:cryptohash:<latest-version>")
}
```

To create a hash first create a digest with `Digest.create` providing the name
of the hash you wish to use, then update with `update` and create the hash with
`digest`:

```kotlin
// Create a digest
val digest = Algorithm.Blake2b_512.createDigest()

// Update the digest with data and generate the hash
digest.update(byteArray)
val hash: ByteArray = digest.digest()

// Alternatively use the shorthand form to update and generate with one function
digest.digest(byteArray)

// HMAC - For algorithms that support HMAC you can create an HMAC digest with a
// key and then use as above
val hmac = Algorithm.SHA3_256.createHmac(key)
```

To use the library directly with Swift on iOS, macOS, tvOS or watchOS, follow
the same pattern as above. To interact with Darwin's [Data](https://developer.apple.com/documentation/foundation/data)
class instead of Kotlin's [ByteArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-byte-array/),
convert the digest into a platform specific implementation with `platform()`:

```swift
// Create a digest
let digest = Algorithm.Blake2b_512().createDigest().platform()

// Update the digest with data and generate the hash
digest.update(data)
let hash: Data = digest.digest()

// Alternatively use the shorthand form to update and generate with one function
digest.digest(data)
```

---

Inspired by the Flutter [crypto](https://pub.dev/packages/crypto)
package. Pure Kotlin implementations based on [saphir](https://github.com/sfuhrm/saphir-hash),
[Bouncy Castle](https://github.com/bcgit/bc-java/), [blake3](https://github.com/rctcwyvrn/blake3).
and [HighwayHash](https://github.com/google/highwayhash/).

[badge-android]: http://img.shields.io/badge/platform-android-6EDB8D.svg?style=flat
[badge-ios]: http://img.shields.io/badge/platform-ios-CDCDCD.svg?style=flat
[badge-js]: http://img.shields.io/badge/platform-js-F8DB5D.svg?style=flat
[badge-jvm]: http://img.shields.io/badge/platform-jvm-DB413D.svg?style=flat
[badge-linux]: http://img.shields.io/badge/platform-linux-2D3F6C.svg?style=flat
[badge-windows]: http://img.shields.io/badge/platform-windows-4D76CD.svg?style=flat
[badge-mac]: http://img.shields.io/badge/platform-macos-111111.svg?style=flat
[badge-watchos]: http://img.shields.io/badge/platform-watchos-C0C0C0.svg?style=flat
[badge-tvos]: http://img.shields.io/badge/platform-tvos-808080.svg?style=flat
[badge-wasm]: https://img.shields.io/badge/platform-wasm-624FE8.svg?style=flat
