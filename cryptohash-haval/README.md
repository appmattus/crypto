# HAVAL

The HAVAL family of hashes, with 3, 4 or 5 passes.

## Installation

Include the following dependency in your *build.gradle.kts* file, or depend on [cryptohash](../cryptohash/README.md) for every algorithm:

```kotlin
commonMain.dependencies {
    implementation("com.appmattus.crypto:cryptohash-haval:<latest-version>")
}
```

Each algorithm hashes in one call with `hash`, or incrementally with the `Hasher` from `newHasher()`. See
[Usage](../cryptohash/README.md#usage) for the full API.

## HAVAL-128-3

HAVAL with 3 passes and output size of 128 bits.

```kotlin
val hash: ByteArray = Haval.haval3_128.hash("Hello, world!")
```

## HAVAL-160-3

HAVAL with 3 passes and output size of 160 bits.

```kotlin
val hash: ByteArray = Haval.haval3_160.hash("Hello, world!")
```

## HAVAL-192-3

HAVAL with 3 passes and output size of 192 bits.

```kotlin
val hash: ByteArray = Haval.haval3_192.hash("Hello, world!")
```

## HAVAL-224-3

HAVAL with 3 passes and output size of 224 bits.

```kotlin
val hash: ByteArray = Haval.haval3_224.hash("Hello, world!")
```

## HAVAL-256-3

HAVAL with 3 passes and output size of 256 bits.

```kotlin
val hash: ByteArray = Haval.haval3_256.hash("Hello, world!")
```

## HAVAL-128-4

HAVAL with 4 passes and output size of 128 bits.

```kotlin
val hash: ByteArray = Haval.haval4_128.hash("Hello, world!")
```

## HAVAL-160-4

HAVAL with 4 passes and output size of 160 bits.

```kotlin
val hash: ByteArray = Haval.haval4_160.hash("Hello, world!")
```

## HAVAL-192-4

HAVAL with 4 passes and output size of 192 bits.

```kotlin
val hash: ByteArray = Haval.haval4_192.hash("Hello, world!")
```

## HAVAL-224-4

HAVAL with 4 passes and output size of 224 bits.

```kotlin
val hash: ByteArray = Haval.haval4_224.hash("Hello, world!")
```

## HAVAL-256-4

HAVAL with 4 passes and output size of 256 bits.

```kotlin
val hash: ByteArray = Haval.haval4_256.hash("Hello, world!")
```

## HAVAL-128-5

HAVAL with 5 passes and output size of 128 bits.

```kotlin
val hash: ByteArray = Haval.haval5_128.hash("Hello, world!")
```

## HAVAL-160-5

HAVAL with 5 passes and output size of 160 bits.

```kotlin
val hash: ByteArray = Haval.haval5_160.hash("Hello, world!")
```

## HAVAL-192-5

HAVAL with 5 passes and output size of 192 bits.

```kotlin
val hash: ByteArray = Haval.haval5_192.hash("Hello, world!")
```

## HAVAL-224-5

HAVAL with 5 passes and output size of 224 bits.

```kotlin
val hash: ByteArray = Haval.haval5_224.hash("Hello, world!")
```

## HAVAL-256-5

HAVAL with 5 passes and output size of 256 bits.

```kotlin
val hash: ByteArray = Haval.haval5_256.hash("Hello, world!")
```
