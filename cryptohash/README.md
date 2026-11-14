# cryptohash

A Kotlin Multiplatform library to provide a set of cryptographic (and
not so cryptographic) hashing functions.

Each family of algorithms is its own module, which you can depend on
individually, and `cryptohash` brings in every one of them. Every algorithm
name below links to its family's page, which shows how to use each of its
variants.

## Algorithms

### Cyclic redundancy checks

- [CRC](../cryptohash-crc/README.md): [CRC32](../cryptohash-crc/README.md#crc32), [CRC32B](../cryptohash-crc/README.md#crc32b), [CRC32C](../cryptohash-crc/README.md#crc32c), [CRC-64/ECMA-182](../cryptohash-crc/README.md#crc-64ecma-182), [CRC-64/XZ](../cryptohash-crc/README.md#crc-64xz), [CRC-64/WE](../cryptohash-crc/README.md#crc-64we), [CRC-64/GO-ISO](../cryptohash-crc/README.md#crc-64go-iso), [CRC-64 SWISS-PROT](../cryptohash-crc/README.md#crc-64-swiss-prot), [CRC-64/REDIS](../cryptohash-crc/README.md#crc-64redis), [CRC-64/NVME](../cryptohash-crc/README.md#crc-64nvme)

### Checksums

- [Adler](../cryptohash-adler/README.md): [Adler32](../cryptohash-adler/README.md#adler32)

### Non-cryptographic hash functions

- [CityHash](../cryptohash-cityhash/README.md#cityhash): [CityHash32](../cryptohash-cityhash/README.md#cityhash32), [CityHash64](../cryptohash-cityhash/README.md#cityhash64), [CityHash128](../cryptohash-cityhash/README.md#cityhash128), [CityHashCrc128](../cryptohash-cityhash/README.md#cityhashcrc128), [CityHashCrc256](../cryptohash-cityhash/README.md#cityhashcrc256)
- [FarmHash](../cryptohash-cityhash/README.md#farmhash): [FarmHash32](../cryptohash-cityhash/README.md#farmhash32), [FarmHash64](../cryptohash-cityhash/README.md#farmhash64), [FarmHash128](../cryptohash-cityhash/README.md#farmhash128)
- [HighwayHash](../cryptohash-highwayhash/README.md): [HighwayHash-64](../cryptohash-highwayhash/README.md#highwayhash-64), [HighwayHash-128](../cryptohash-highwayhash/README.md#highwayhash-128), [HighwayHash-256](../cryptohash-highwayhash/README.md#highwayhash-256)
- [komihash](../cryptohash-komihash/README.md): [komihash](../cryptohash-komihash/README.md#komihash)
- [MetroHash](../cryptohash-metrohash/README.md): [MetroHash64](../cryptohash-metrohash/README.md#metrohash64), [MetroHash128](../cryptohash-metrohash/README.md#metrohash128)
- [MurmurHash](../cryptohash-murmurhash/README.md): [MurmurHash1](../cryptohash-murmurhash/README.md#murmurhash1), [MurmurHash2](../cryptohash-murmurhash/README.md#murmurhash2), [MurmurHash64A](../cryptohash-murmurhash/README.md#murmurhash64a), [MurmurHash64B](../cryptohash-murmurhash/README.md#murmurhash64b), [MurmurHash2A](../cryptohash-murmurhash/README.md#murmurhash2a) (aka CMurmurHash2A), [MurmurHash3-x86-32](../cryptohash-murmurhash/README.md#murmurhash3-x86-32), [MurmurHash3-x86-128](../cryptohash-murmurhash/README.md#murmurhash3-x86-128), [MurmurHash3-x64-128](../cryptohash-murmurhash/README.md#murmurhash3-x64-128)
- [rapidhash](../cryptohash-rapidhash/README.md): [rapidhash](../cryptohash-rapidhash/README.md#rapidhash), [rapidhashMicro](../cryptohash-rapidhash/README.md#rapidhashmicro), [rapidhashNano](../cryptohash-rapidhash/README.md#rapidhashnano)
- [t1ha](../cryptohash-t1ha/README.md): [t1ha0-32le](../cryptohash-t1ha/README.md#t1ha0-32le), [t1ha1-le](../cryptohash-t1ha/README.md#t1ha1-le), [t1ha2-atonce](../cryptohash-t1ha/README.md#t1ha2-atonce), [t1ha2-atonce128](../cryptohash-t1ha/README.md#t1ha2-atonce128), [t1ha2-stream](../cryptohash-t1ha/README.md#t1ha2-stream), [t1ha2-stream128](../cryptohash-t1ha/README.md#t1ha2-stream128)
- [xxHash](../cryptohash-xxhash/README.md): [xxHash-32](../cryptohash-xxhash/README.md#xxhash-32), [xxHash-64](../cryptohash-xxhash/README.md#xxhash-64), [xxHash3-64](../cryptohash-xxhash/README.md#xxhash3-64), [xxHash3-128](../cryptohash-xxhash/README.md#xxhash3-128)
- [wyhash](../cryptohash-wyhash/README.md): [wyhash32](../cryptohash-wyhash/README.md#wyhash32), [wyhash](../cryptohash-wyhash/README.md#wyhash) (aka wyhash64)

### Keyed cryptographic hash functions

- [BLAKE2](../cryptohash-blake2/README.md): [Blake2b keyed](../cryptohash-blake2/README.md#blake2b-keyed), [Blake2s keyed](../cryptohash-blake2/README.md#blake2s-keyed)
- [BLAKE3](../cryptohash-blake3/README.md): [Blake3 keyed](../cryptohash-blake3/README.md#blake3-keyed), [Blake3 key derivation](../cryptohash-blake3/README.md#blake3-key-derivation)
- HMAC: [HMAC](#hmac) (with every algorithm that supports it)
- [SP 800-185](../cryptohash-keccak/README.md#sp-800-185): [KMAC128](../cryptohash-keccak/README.md#kmac128), [KMAC256](../cryptohash-keccak/README.md#kmac256)
- [SipHash](../cryptohash-siphash/README.md): [SipHash](../cryptohash-siphash/README.md#siphash) (SipHash-2-4 by default), [SipHash128](../cryptohash-siphash/README.md#siphash128) (SipHash128-2-4 by default)
- [Skein](../cryptohash-skein/README.md): [Skein MAC](../cryptohash-skein/README.md#skein-mac)

### Unkeyed cryptographic hash functions

- [Ascon](../cryptohash-ascon/README.md): [Ascon-Hash256](../cryptohash-ascon/README.md#ascon-hash256), [Ascon-XOF128](../cryptohash-ascon/README.md#ascon-xof128), [Ascon-CXOF128](../cryptohash-ascon/README.md#ascon-cxof128)
- [BLAKE](../cryptohash-blake/README.md): [BLAKE-224](../cryptohash-blake/README.md#blake-224), [BLAKE-256](../cryptohash-blake/README.md#blake-256), [BLAKE-384](../cryptohash-blake/README.md#blake-384), [BLAKE-512](../cryptohash-blake/README.md#blake-512)
- [BLAKE2](../cryptohash-blake2/README.md): [Blake2b](../cryptohash-blake2/README.md#blake2b), [Blake2s](../cryptohash-blake2/README.md#blake2s)
- [BLAKE3](../cryptohash-blake3/README.md): [Blake3](../cryptohash-blake3/README.md#blake3)
- [Blue Midnight Wish](../cryptohash-bmw/README.md): [BMW-224](../cryptohash-bmw/README.md#bmw-224), [BMW-256](../cryptohash-bmw/README.md#bmw-256), [BMW-384](../cryptohash-bmw/README.md#bmw-384), [BMW-512](../cryptohash-bmw/README.md#bmw-512)
- [CubeHash](../cryptohash-cubehash/README.md): [CubeHash-224](../cryptohash-cubehash/README.md#cubehash-224), [CubeHash-256](../cryptohash-cubehash/README.md#cubehash-256), [CubeHash-384](../cryptohash-cubehash/README.md#cubehash-384), [CubeHash-512](../cryptohash-cubehash/README.md#cubehash-512)
- [ECHO](../cryptohash-echo/README.md): [ECHO-224](../cryptohash-echo/README.md#echo-224), [ECHO-256](../cryptohash-echo/README.md#echo-256), [ECHO-384](../cryptohash-echo/README.md#echo-384), [ECHO-512](../cryptohash-echo/README.md#echo-512)
- [Fugue](../cryptohash-fugue/README.md): [Fugue-224](../cryptohash-fugue/README.md#fugue-224), [Fugue-256](../cryptohash-fugue/README.md#fugue-256), [Fugue-384](../cryptohash-fugue/README.md#fugue-384), [Fugue-512](../cryptohash-fugue/README.md#fugue-512)
- [GOST R 34.11-94](../cryptohash-gost/README.md): [GOST3411-94](../cryptohash-gost/README.md#gost3411-94)
- [Grøstl](../cryptohash-groestl/README.md): [Groestl-224](../cryptohash-groestl/README.md#groestl-224), [Groestl-256](../cryptohash-groestl/README.md#groestl-256), [Groestl-384](../cryptohash-groestl/README.md#groestl-384), [Groestl-512](../cryptohash-groestl/README.md#groestl-512)
- [Hamsi](../cryptohash-hamsi/README.md): [Hamsi-224](../cryptohash-hamsi/README.md#hamsi-224), [Hamsi-256](../cryptohash-hamsi/README.md#hamsi-256), [Hamsi-384](../cryptohash-hamsi/README.md#hamsi-384), [Hamsi-512](../cryptohash-hamsi/README.md#hamsi-512)
- [Haraka](../cryptohash-haraka/README.md): [Haraka-256](../cryptohash-haraka/README.md#haraka-256), [Haraka-512](../cryptohash-haraka/README.md#haraka-512)
- [HAVAL](../cryptohash-haval/README.md): [HAVAL-128-3](../cryptohash-haval/README.md#haval-128-3), [HAVAL-128-4](../cryptohash-haval/README.md#haval-128-4), [HAVAL-128-5](../cryptohash-haval/README.md#haval-128-5), [HAVAL-160-3](../cryptohash-haval/README.md#haval-160-3), [HAVAL-160-4](../cryptohash-haval/README.md#haval-160-4), [HAVAL-160-5](../cryptohash-haval/README.md#haval-160-5), [HAVAL-192-3](../cryptohash-haval/README.md#haval-192-3), [HAVAL-192-4](../cryptohash-haval/README.md#haval-192-4), [HAVAL-192-5](../cryptohash-haval/README.md#haval-192-5), [HAVAL-224-3](../cryptohash-haval/README.md#haval-224-3), [HAVAL-224-4](../cryptohash-haval/README.md#haval-224-4), [HAVAL-224-5](../cryptohash-haval/README.md#haval-224-5), [HAVAL-256-3](../cryptohash-haval/README.md#haval-256-3), [HAVAL-256-4](../cryptohash-haval/README.md#haval-256-4), [HAVAL-256-5](../cryptohash-haval/README.md#haval-256-5)
- [JH](../cryptohash-jh/README.md): [JH-224](../cryptohash-jh/README.md#jh-224), [JH-256](../cryptohash-jh/README.md#jh-256), [JH-384](../cryptohash-jh/README.md#jh-384), [JH-512](../cryptohash-jh/README.md#jh-512)
- [Keccak](../cryptohash-keccak/README.md#keccak): [Keccak-224](../cryptohash-keccak/README.md#keccak-224), [Keccak-256](../cryptohash-keccak/README.md#keccak-256), [Keccak-288](../cryptohash-keccak/README.md#keccak-288), [Keccak-384](../cryptohash-keccak/README.md#keccak-384), [Keccak-512](../cryptohash-keccak/README.md#keccak-512)
- [KangarooTwelve](../cryptohash-keccak/README.md#kangarootwelve): [KT128](../cryptohash-keccak/README.md#kt128) (aka KangarooTwelve), [KT256](../cryptohash-keccak/README.md#kt256)
- [Kupyna](../cryptohash-kupyna/README.md): [Kupyna-256](../cryptohash-kupyna/README.md#kupyna-256) (aka DSTU7564-256), [Kupyna-384](../cryptohash-kupyna/README.md#kupyna-384) (aka DSTU7564-384), [Kupyna-512](../cryptohash-kupyna/README.md#kupyna-512) (aka DSTU7564-512)
- [Luffa](../cryptohash-luffa/README.md): [Luffa-224](../cryptohash-luffa/README.md#luffa-224), [Luffa-256](../cryptohash-luffa/README.md#luffa-256), [Luffa-384](../cryptohash-luffa/README.md#luffa-384), [Luffa-512](../cryptohash-luffa/README.md#luffa-512)
- [MD](../cryptohash-md/README.md): [MD2](../cryptohash-md/README.md#md2), [MD4](../cryptohash-md/README.md#md4), [MD5](../cryptohash-md/README.md#md5)
- [PANAMA](../cryptohash-panama/README.md): [PANAMA](../cryptohash-panama/README.md#panama)
- [RadioGatún](../cryptohash-radiogatun/README.md): [RadioGatun32](../cryptohash-radiogatun/README.md#radiogatun32), [RadioGatun64](../cryptohash-radiogatun/README.md#radiogatun64)
- [RIPEMD](../cryptohash-ripemd/README.md): [RIPEMD](../cryptohash-ripemd/README.md#ripemd), [RIPEMD-128](../cryptohash-ripemd/README.md#ripemd-128), [RIPEMD-160](../cryptohash-ripemd/README.md#ripemd-160), [RIPEMD-256](../cryptohash-ripemd/README.md#ripemd-256), [RIPEMD-320](../cryptohash-ripemd/README.md#ripemd-320)
- [SHA-1](../cryptohash-sha1/README.md): [SHA-0](../cryptohash-sha1/README.md#sha-0), [SHA-1](../cryptohash-sha1/README.md#sha-1)
- [SHA-2](../cryptohash-sha2/README.md): [SHA-224](../cryptohash-sha2/README.md#sha-224), [SHA-256](../cryptohash-sha2/README.md#sha-256), [SHA-384](../cryptohash-sha2/README.md#sha-384), [SHA-512](../cryptohash-sha2/README.md#sha-512), [SHA-512/224](../cryptohash-sha2/README.md#sha-512224), [SHA-512/256](../cryptohash-sha2/README.md#sha-512256)
- [SHA-3](../cryptohash-keccak/README.md#sha-3): [SHA3-224](../cryptohash-keccak/README.md#sha3-224), [SHA3-256](../cryptohash-keccak/README.md#sha3-256), [SHA3-384](../cryptohash-keccak/README.md#sha3-384), [SHA3-512](../cryptohash-keccak/README.md#sha3-512), [SHAKE128](../cryptohash-keccak/README.md#shake128), [SHAKE256](../cryptohash-keccak/README.md#shake256)
- [SP 800-185](../cryptohash-keccak/README.md#sp-800-185): [cSHAKE128](../cryptohash-keccak/README.md#cshake128), [cSHAKE256](../cryptohash-keccak/README.md#cshake256), [ParallelHash128](../cryptohash-keccak/README.md#parallelhash128), [ParallelHash256](../cryptohash-keccak/README.md#parallelhash256), [TupleHash128](../cryptohash-keccak/README.md#tuplehash128), [TupleHash256](../cryptohash-keccak/README.md#tuplehash256)
- [Shabal](../cryptohash-shabal/README.md): [Shabal-192](../cryptohash-shabal/README.md#shabal-192), [Shabal-224](../cryptohash-shabal/README.md#shabal-224), [Shabal-256](../cryptohash-shabal/README.md#shabal-256), [Shabal-384](../cryptohash-shabal/README.md#shabal-384), [Shabal-512](../cryptohash-shabal/README.md#shabal-512)
- [SHAvite-3](../cryptohash-shavite/README.md): [SHAvite-224](../cryptohash-shavite/README.md#shavite-224), [SHAvite-256](../cryptohash-shavite/README.md#shavite-256), [SHAvite-384](../cryptohash-shavite/README.md#shavite-384), [SHAvite-512](../cryptohash-shavite/README.md#shavite-512)
- [SIMD](../cryptohash-simd/README.md): [SIMD-224](../cryptohash-simd/README.md#simd-224), [SIMD-256](../cryptohash-simd/README.md#simd-256), [SIMD-384](../cryptohash-simd/README.md#simd-384), [SIMD-512](../cryptohash-simd/README.md#simd-512)
- [Skein](../cryptohash-skein/README.md): [Skein-256-128](../cryptohash-skein/README.md#skein-256-128), [Skein-256-160](../cryptohash-skein/README.md#skein-256-160), [Skein-256-224](../cryptohash-skein/README.md#skein-256-224), [Skein-256-256](../cryptohash-skein/README.md#skein-256-256), [Skein-512-128](../cryptohash-skein/README.md#skein-512-128), [Skein-512-160](../cryptohash-skein/README.md#skein-512-160), [Skein-512-224](../cryptohash-skein/README.md#skein-512-224), [Skein-512-256](../cryptohash-skein/README.md#skein-512-256), [Skein-512-384](../cryptohash-skein/README.md#skein-512-384), [Skein-512-512](../cryptohash-skein/README.md#skein-512-512), [Skein-1024-384](../cryptohash-skein/README.md#skein-1024-384), [Skein-1024-512](../cryptohash-skein/README.md#skein-1024-512), [Skein-1024-1024](../cryptohash-skein/README.md#skein-1024-1024), [Skein with any sizes](../cryptohash-skein/README.md#skein-with-any-sizes)
- [SM3](../cryptohash-sm3/README.md): [SM3](../cryptohash-sm3/README.md#sm3)
- [Streebog](../cryptohash-streebog/README.md): [Streebog-256](../cryptohash-streebog/README.md#streebog-256) (aka GOST3411-2012-256), [Streebog-512](../cryptohash-streebog/README.md#streebog-512) (aka GOST3411-2012-512)
- [Tiger](../cryptohash-tiger/README.md): [Tiger](../cryptohash-tiger/README.md#tiger), [Tiger2](../cryptohash-tiger/README.md#tiger2)
- [Whirlpool](../cryptohash-whirlpool/README.md): [Whirlpool](../cryptohash-whirlpool/README.md#whirlpool), [Whirlpool-0](../cryptohash-whirlpool/README.md#whirlpool-0), [Whirlpool-T](../cryptohash-whirlpool/README.md#whirlpool-t)

## Getting started

![badge][badge-android]
![badge][badge-ios]
![badge][badge-watchos]
![badge][badge-tvos]
![badge][badge-mac]
![badge][badge-linux]
![badge][badge-windows]
![badge][badge-jvm]
![badge][badge-js]
![badge][badge-wasm]
[![Maven Central](https://img.shields.io/maven-central/v/com.appmattus.crypto/cryptohash)](https://search.maven.org/search?q=g:com.appmattus.crypto)

Include the following dependency in your *build.gradle.kts* file for every
algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash:<latest-version>")
}
```

Or depend on just the families you need, each of which is listed on its own
page, for example:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-sha2:<latest-version>")
    implementation("com.appmattus.crypto:cryptohash-blake3:<latest-version>")
}
```

## Usage

Every algorithm is a `HashAlgorithm`, found on its family's object, such as
`Sha2.sha256` or `Blake3.blake3()`. Hash in one call with `hash`, or
incrementally with the `Hasher` from `newHasher()`:

```kotlin
// Hash in one call, from an array, part of an array or the UTF-8 encoding of a string
val hash: ByteArray = Sha2.sha256.hash(byteArray)
val part: ByteArray = Sha2.sha256.hash(byteArray, offset, length)
val text: ByteArray = Sha2.sha256.hash("Hello, world!")

// Or create a hasher and update it with data before generating the hash
val hasher = Blake2.blake2b().newHasher()
hasher.update(byteArray)
val incremental: ByteArray = hasher.digest()

// update returns the hasher, so calls can be chained, and digest resets it, ready for the next hash
val chained: ByteArray = hasher.update(part1).update(part2).digest()

// Alternatively update and generate the hash with one function
val shorthand: ByteArray = hasher.digest(byteArray)

// copy a hasher to hash several inputs that share a prefix
val prefix = Sha2.sha256.newHasher().update(header)
val first: ByteArray = prefix.copy().update(body1).digest()
val second: ByteArray = prefix.copy().update(body2).digest()

// Kotlin's standard library converts a hash to hex
val hex: String = Sha2.sha256.hash("Hello, world!").toHexString()
```

### HMAC

Algorithms that support HMAC are an `HmacAlgorithm`, and say so on their
family's page. Create a `Mac` with a key, and use it as you would a `Hasher`:

```kotlin
val key = "my secret key".encodeToByteArray()

// The HMAC of a message
val mac: ByteArray = Sha2.sha256.newHmac(key).digest(message)

// Truncated to the first 16 bytes
val truncated: ByteArray = Sha2.sha256.newHmac(key, outputLength = 16).digest(message)

// Check an HMAC you were sent, in constant time
val valid: Boolean = Sha2.sha256.newHmac(key).update(message).verify(receivedMac)
```

Keyed algorithms that aren't HMAC, such as `Blake3.blake3Keyed`,
`SipHash.sipHash` and `Sp800185.kmac128`, take their key when you create the
algorithm, and are then used like any other `HashAlgorithm`.

### Swift

The library works directly from Swift on iOS, macOS, tvOS and watchOS. Each
family is a Kotlin object, reached through `shared`, and Kotlin's `ByteArray`
is `KotlinByteArray`:

```swift
let hash: KotlinByteArray = Sha2.shared.sha256.hash(input: "Hello, world!")

let hasher = Blake2.shared.blake2b(outputSizeBits: 512).newHasher()
hasher.update(input: bytes)
let digest: KotlinByteArray = hasher.digest()
```

### Migrating from Algorithm

The `Algorithm` API is deprecated. Each `Algorithm` names its replacement in
its deprecation message, and most can be replaced automatically from the IDE:

| Deprecated                                    | Replacement                                     |
|-----------------------------------------------|-------------------------------------------------|
| `Algorithm.SHA_256.createDigest()`            | `Sha2.sha256.newHasher()`                       |
| `Algorithm.SHA_256.hash(input)`               | `Sha2.sha256.hash(input)`                       |
| `Algorithm.Blake2b(256).createDigest()`       | `Blake2.blake2b(256).newHasher()`               |
| `Algorithm.SHA3_256.createHmac(key)`          | `Sha3.sha3_256.newHmac(key)`                    |
| `Algorithm.SHA_256.hmac(key, input)`          | `Sha2.sha256.newHmac(key).digest(input)`        |
| `Digest`                                      | `Hasher`                                        |
| `digest.platform()`, `PlatformDigest`         | `Hasher`, with `ByteArray` input and output     |

---

Inspired by the Flutter [crypto](https://pub.dev/packages/crypto)
package. Pure Kotlin implementations based on [saphir](https://github.com/sfuhrm/saphir-hash),
[Bouncy Castle](https://github.com/bcgit/bc-java/), [blake3](https://github.com/rctcwyvrn/blake3)
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
