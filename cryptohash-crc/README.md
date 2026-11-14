# CRC

Cyclic redundancy checks, in their 32-bit and 64-bit variants.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-crc:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## CRC32

CRC-32/BZIP2, the non-reflected CRC-32 with polynomial 0x04C11DB7, with output size of 32 bits.

```kotlin
val hash: ByteArray = Crc.crc32.hash("Hello, world!")
```

## CRC32B

CRC-32/ISO-HDLC, the reflected CRC-32 of zlib, gzip, PNG and Ethernet, with output size of 32 bits.

```kotlin
val hash: ByteArray = Crc.crc32b.hash("Hello, world!")
```

## CRC32C

CRC-32C/ISCSI, Castagnoli's CRC used by iSCSI, SCTP, Btrfs and ext4, with output size of 32 bits.

```kotlin
val hash: ByteArray = Crc.crc32c.hash("Hello, world!")
```

## CRC-64/ECMA-182

CRC-64/ECMA-182, the non-reflected CRC-64 of ECMA-182 with polynomial 0x42F0E1EBA9EA3693, initial value 0 and no final XOR.

```kotlin
val hash: ByteArray = Crc.crc64Ecma182.hash("Hello, world!")
```

## CRC-64/XZ

CRC-64/XZ, the reflected CRC-64 with the ECMA-182 polynomial used by XZ and Go's ECMA table, with initial value and final XOR of all ones.

```kotlin
val hash: ByteArray = Crc.crc64Xz.hash("Hello, world!")
```

## CRC-64/WE

CRC-64/WE, the non-reflected CRC-64 with the ECMA-182 polynomial, initial value and final XOR of all ones. This is Linux's crc64_be as bcache uses it; crc64_be with an initial value of 0 and no final XOR is `crc64Ecma182`.

```kotlin
val hash: ByteArray = Crc.crc64We.hash("Hello, world!")
```

## CRC-64/GO-ISO

CRC-64/GO-ISO, the reflected CRC-64 with the ISO polynomial 0x1B used by Go's ISO table, with initial value and final XOR of all ones.

```kotlin
val hash: ByteArray = Crc.crc64GoIso.hash("Hello, world!")
```

## CRC-64 SWISS-PROT

The reflected CRC-64 with the ISO polynomial 0x1B as SWISS-PROT and UniProt use it, with initial value 0 and no final XOR.

```kotlin
val hash: ByteArray = Crc.crc64SwissProt.hash("Hello, world!")
```

## CRC-64/REDIS

CRC-64/REDIS, the reflected CRC-64 with Jones's polynomial 0xAD93D23594C935A9 used by Redis, also known as CRC-64-Jones, with initial value 0 and no final XOR.

```kotlin
val hash: ByteArray = Crc.crc64Redis.hash("Hello, world!")
```

## CRC-64/NVME

CRC-64/NVME, the reflected CRC-64 with polynomial 0xAD93D23594C93659 of NVMe and Linux's crc64_nvme, also known as the Rocksoft CRC, with initial value and final XOR of all ones.

```kotlin
val hash: ByteArray = Crc.crc64Nvme.hash("Hello, world!")
```
