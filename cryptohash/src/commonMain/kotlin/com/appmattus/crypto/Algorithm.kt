/*
 * Copyright 2022-2026 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.crypto

import com.appmattus.crypto.internal.CoreDigest
import com.appmattus.crypto.internal.xxhash.xxh3.XXH3_SECRET_SIZE_MIN

@Suppress("ClassName", "DEPRECATION")
@Deprecated(
    "Use the algorithm family objects in the cryptohash modules, such as Sha2.sha256, which create a Hasher with " +
        "newHasher(), hash with hash() and, for HMAC, create a Mac with newHmac()"
)
public sealed class Algorithm(public val algorithmName: String, internal val blockLength: Int) {

    /**
     * The named parameters, beyond [algorithmName], that configure this [Algorithm]. Used to implement [equals],
     * [hashCode] and [toString] for algorithms that are not data classes or objects.
     */
    internal open val parameters: List<Pair<String, Any?>>
        get() = emptyList()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        // The name is compared before the class as it's far cheaper, notably on Kotlin/JS where each ::class is a lookup,
        // and almost every mismatch differs by name. CoreDigest.create compares against each algorithm in turn.
        if (other !is Algorithm || algorithmName != other.algorithmName || this::class != other::class) return false
        val otherParameters = other.parameters
        return parameters.size == otherParameters.size &&
            parameters.indices.all { parameterEquals(parameters[it].second, otherParameters[it].second) }
    }

    override fun hashCode(): Int = parameters.fold(algorithmName.hashCode()) { acc, (_, value) -> 31 * acc + parameterHashCode(value) }

    /**
     * The [algorithmName] followed by any [parameters]. Array and collection parameters, such as keys and secrets, are
     * shown by size only.
     */
    override fun toString(): String = if (parameters.isEmpty()) {
        algorithmName
    } else {
        parameters.joinToString(prefix = "$algorithmName(", postfix = ")") { (name, value) -> "$name=${parameterToString(value)}" }
    }

    /**
     * [Adler-32](https://en.wikipedia.org/wiki/Adler-32) with output size of 32 bits
     */
    @Deprecated(
        "Use Adler.adler32 from cryptohash-adler",
        ReplaceWith("Adler.adler32", "com.appmattus.crypto.Adler")
    )
    public data object Adler32 : Algorithm("Adler32", 32)

    /**
     * [Ascon-Hash256](https://doi.org/10.6028/NIST.SP.800-232) from NIST SP 800-232 with output size of 256 bits
     */
    @Deprecated(
        "Use Ascon.hash256 from cryptohash-ascon",
        ReplaceWith("Ascon.hash256", "com.appmattus.crypto.Ascon")
    )
    public data object AsconHash256 : Algorithm("Ascon-Hash256", 8)

    /**
     * [Ascon-XOF128](https://doi.org/10.6028/NIST.SP.800-232) from NIST SP 800-232 with output size of
     * [outputSizeBits] bits (default: 256 bits)
     */
    @Deprecated("Use Ascon.xof128 from cryptohash-ascon")
    public class AsconXof128(internal val outputSizeBits: Int = 256) : Algorithm("Ascon-XOF128", 8) {
        init {
            requireValidAsconOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("outputSizeBits" to outputSizeBits)
    }

    /**
     * [Ascon-CXOF128](https://doi.org/10.6028/NIST.SP.800-232) from NIST SP 800-232, the customisable variant of
     * [AsconXof128], with a [customisation] string of at most 256 bytes and output size of [outputSizeBits] bits
     * (default: 256 bits)
     */
    @Deprecated("Use Ascon.cxof128 from cryptohash-ascon")
    public class AsconCXof128(
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 256
    ) : Algorithm("Ascon-CXOF128", 8) {
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            require((customisation?.size ?: 0) <= ASCON_CUSTOMISATION_MAX_SIZE) {
                "customisation must be at most $ASCON_CUSTOMISATION_MAX_SIZE bytes, was ${customisation?.size}"
            }
            requireValidAsconOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 224 bits
     */
    @Deprecated(
        "Use Blake.blake224 from cryptohash-blake",
        ReplaceWith("Blake.blake224", "com.appmattus.crypto.Blake")
    )
    public data object BLAKE224 : Algorithm("BLAKE-224", 64)

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 256 bits
     */
    @Deprecated(
        "Use Blake.blake256 from cryptohash-blake",
        ReplaceWith("Blake.blake256", "com.appmattus.crypto.Blake")
    )
    public data object BLAKE256 : Algorithm("BLAKE-256", 64)

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 384 bits
     */
    @Deprecated(
        "Use Blake.blake384 from cryptohash-blake",
        ReplaceWith("Blake.blake384", "com.appmattus.crypto.Blake")
    )
    public data object BLAKE384 : Algorithm("BLAKE-384", 128)

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 512 bits
     */
    @Deprecated(
        "Use Blake.blake512 from cryptohash-blake",
        ReplaceWith("Blake.blake512", "com.appmattus.crypto.Blake")
    )
    public data object BLAKE512 : Algorithm("BLAKE-512", 128)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 128 bits
     */
    @Deprecated(
        "Use Blake2.blake2s(128) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2s(128)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2s_128 : Algorithm("Blake2s-128", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 160 bits
     */
    @Deprecated(
        "Use Blake2.blake2s(160) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2s(160)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2s_160 : Algorithm("Blake2s-160", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 224 bits
     */
    @Deprecated(
        "Use Blake2.blake2s(224) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2s(224)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2s_224 : Algorithm("Blake2s-224", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 256 bits
     */
    @Deprecated(
        "Use Blake2.blake2s(256) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2s(256)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2s_256 : Algorithm("Blake2s-256", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of [outputSizeBits] bits (default: 256 bits)
     */
    @Deprecated("Use Blake2.blake2sKeyed or Blake2.blake2s from cryptohash-blake2")
    public open class Blake2s(internal val outputSizeBits: Int = 256) : Algorithm("Blake2s-$outputSizeBits", 64) {
        init {
            require(outputSizeBits in 8..256 && outputSizeBits % 8 == 0) {
                "outputSizeBits must be a multiple of 8 between 8 and 256, was $outputSizeBits"
            }
        }

        /**
         * [Blake2s] tuned to your specific requirements, such as [key]ed hashing, hashing with a [salt], or
         * [personalisation], or any combination thereof with output size of [outputSizeBits] bits (default: 256 bits)
         */
        public class Keyed(
            key: ByteArray,
            salt: ByteArray? = null,
            personalisation: ByteArray? = null,
            outputSizeBits: Int = 256
        ) : Blake2s(outputSizeBits) {
            internal val key: ByteArray = key.copyOf()
            internal val salt: ByteArray? = salt?.copyOf()
            internal val personalisation: ByteArray? = personalisation?.copyOf()

            init {
                require(key.size <= 32) { "key must be at most 32 bytes, was ${key.size}" }
                require(salt == null || salt.size == 8) { "salt must be exactly 8 bytes, was ${salt?.size}" }
                require(personalisation == null || personalisation.size == 8) {
                    "personalisation must be exactly 8 bytes, was ${personalisation?.size}"
                }
            }

            override val parameters: List<Pair<String, Any?>>
                get() = listOf("key" to key, "salt" to salt, "personalisation" to personalisation)
        }
    }

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 160 bits
     */
    @Deprecated(
        "Use Blake2.blake2b(160) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2b(160)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2b_160 : Algorithm("Blake2b-160", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 256 bits
     */
    @Deprecated(
        "Use Blake2.blake2b(256) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2b(256)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2b_256 : Algorithm("Blake2b-256", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 384 bits
     */
    @Deprecated(
        "Use Blake2.blake2b(384) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2b(384)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2b_384 : Algorithm("Blake2b-384", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 512 bits
     */
    @Deprecated(
        "Use Blake2.blake2b(512) from cryptohash-blake2",
        ReplaceWith("Blake2.blake2b(512)", "com.appmattus.crypto.Blake2")
    )
    public data object Blake2b_512 : Algorithm("Blake2b-512", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of [outputSizeBits] bits (default: 512 bits)
     */
    @Deprecated("Use Blake2.blake2bKeyed or Blake2.blake2b from cryptohash-blake2")
    public open class Blake2b(internal val outputSizeBits: Int = 512) : Algorithm("Blake2b-$outputSizeBits", 128) {
        init {
            require(outputSizeBits in 8..512 && outputSizeBits % 8 == 0) {
                "outputSizeBits must be a multiple of 8 between 8 and 512, was $outputSizeBits"
            }
        }

        /**
         * [Blake2b] tuned to your specific requirements, such as [key]ed hashing, hashing with a [salt], or
         * [personalisation], or any combination thereof with output size of [outputSizeBits] bits (default: 512 bits)
         */
        public class Keyed(
            key: ByteArray,
            salt: ByteArray? = null,
            personalisation: ByteArray? = null,
            outputSizeBits: Int = 512
        ) : Blake2b(outputSizeBits) {
            internal val key: ByteArray = key.copyOf()
            internal val salt: ByteArray? = salt?.copyOf()
            internal val personalisation: ByteArray? = personalisation?.copyOf()

            init {
                require(key.size <= 64) { "key must be at most 64 bytes, was ${key.size}" }
                require(salt == null || salt.size == 16) { "salt must be exactly 16 bytes, was ${salt?.size}" }
                require(personalisation == null || personalisation.size == 16) {
                    "personalisation must be exactly 16 bytes, was ${personalisation?.size}"
                }
            }

            override val parameters: List<Pair<String, Any?>>
                get() = listOf("key" to key, "salt" to salt, "personalisation" to personalisation)
        }
    }

    /**
     * [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) with output size of [digestLength] bytes (default: 32 bytes)
     */
    @Deprecated("Use Blake3.blake3Keyed, Blake3.blake3DeriveKey or Blake3.blake3 from cryptohash-blake3")
    public open class Blake3(internal val digestLength: Int = BLAKE3_DEFAULT_DIGEST_LENGTH) : Algorithm("Blake3-${digestLength shl 3}", 64) {
        init {
            require(digestLength > 0) { "digestLength must be greater than 0, was $digestLength" }
        }

        /**
         * [Blake3] using [key]ed hashing with output size of [digestLength] bytes (default: 32 bytes)
         */
        public class Keyed(key: ByteArray, digestLength: Int = BLAKE3_DEFAULT_DIGEST_LENGTH) : Blake3(digestLength) {
            internal val key: ByteArray = key.copyOf()

            init {
                require(key.size == BLAKE3_KEY_SIZE) { "key must be exactly ${BLAKE3_KEY_SIZE} bytes, was ${key.size}" }
            }

            override val parameters: List<Pair<String, Any?>>
                get() = listOf("key" to key)
        }

        /**
         * [Blake3] using [context] to derive a key with output size of [digestLength] bytes (default: 32 bytes)
         */
        public class DeriveKey(context: ByteArray, digestLength: Int = BLAKE3_DEFAULT_DIGEST_LENGTH) : Blake3(digestLength) {
            internal val context: ByteArray = context.copyOf()
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("context" to context)
        }
    }

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 224 bits
     */
    @Deprecated(
        "Use Bmw.bmw224 from cryptohash-bmw",
        ReplaceWith("Bmw.bmw224", "com.appmattus.crypto.Bmw")
    )
    public data object BMW224 : Algorithm("BMW-224", 64), Hmac

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 256 bits
     */
    @Deprecated(
        "Use Bmw.bmw256 from cryptohash-bmw",
        ReplaceWith("Bmw.bmw256", "com.appmattus.crypto.Bmw")
    )
    public data object BMW256 : Algorithm("BMW-256", 64), Hmac

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 384 bits
     */
    @Deprecated(
        "Use Bmw.bmw384 from cryptohash-bmw",
        ReplaceWith("Bmw.bmw384", "com.appmattus.crypto.Bmw")
    )
    public data object BMW384 : Algorithm("BMW-384", 128), Hmac

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 512 bits
     */
    @Deprecated(
        "Use Bmw.bmw512 from cryptohash-bmw",
        ReplaceWith("Bmw.bmw512", "com.appmattus.crypto.Bmw")
    )
    public data object BMW512 : Algorithm("BMW-512", 128), Hmac

    /**
     * [CityHash](https://github.com/google/cityhash) with output size of 32 bits
     */
    @Deprecated(
        "Use CityHash.cityHash32 from cryptohash-cityhash",
        ReplaceWith("CityHash.cityHash32", "com.appmattus.crypto.CityHash")
    )
    public data object CityHash32 : Algorithm("CityHash32", 4)

    /**
     * [CityHash](https://github.com/google/cityhash) with output size of 64 bits
     */
    @Deprecated("Use CityHash.cityHash64 from cryptohash-cityhash")
    public open class CityHash64 : Algorithm("CityHash64", 8) {
        /**
         * [CityHash64] using [seed] with output size of 64 bits
         */
        public class Seed(internal val seed: ULong) : CityHash64() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seed" to seed)
        }

        /**
         * [CityHash64] using [seed1] and [seed2] with output size of 64 bits
         */
        public class Seeds(internal val seed1: ULong, internal val seed2: ULong) : CityHash64() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seed1" to seed1, "seed2" to seed2)
        }
    }

    /**
     * [CityHash](https://github.com/google/cityhash) with output size of 128 bits
     */
    @Deprecated("Use CityHash.cityHash128 from cryptohash-cityhash")
    public open class CityHash128 : Algorithm("CityHash128", 16) {
        /**
         * [CityHash128] using seed ([seedLow] & [seedHigh]) with output size of 128 bits
         */
        public class Seed(internal val seedLow: ULong, internal val seedHigh: ULong) : CityHash128() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seedLow" to seedLow, "seedHigh" to seedHigh)
        }
    }

    /**
     * [CityHash](https://github.com/google/cityhash) with output size of 128 bits
     */
    @Deprecated("Use CityHash.cityHashCrc128 from cryptohash-cityhash")
    public open class CityHashCrc128 : Algorithm("CityHashCrc128", 16) {
        /**
         * [CityHash128] using seed ([seedLow] & [seedHigh]) with output size of 128 bits
         */
        public class Seed(internal val seedLow: ULong, internal val seedHigh: ULong) : CityHashCrc128() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seedLow" to seedLow, "seedHigh" to seedHigh)
        }
    }

    /**
     * [CityHash](https://github.com/google/cityhash) with output size of 256 bits
     */
    @Deprecated(
        "Use CityHash.cityHashCrc256 from cryptohash-cityhash",
        ReplaceWith("CityHash.cityHashCrc256", "com.appmattus.crypto.CityHash")
    )
    public data object CityHashCrc256 : Algorithm("CityHashCrc256", 32)

    /**
     * [Crc](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) with output size of 32 bits.
     * Used by bzip.
     */
    @Deprecated(
        "Use Crc.crc32 from cryptohash-crc",
        ReplaceWith("Crc.crc32", "com.appmattus.crypto.Crc")
    )
    public data object CRC32 : Algorithm("CRC32", 32)

    /**
     * [Crc](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) with output size of 32 bits.
     * Used by ethernet (IEEE 802.3), gzip, zip, png, etc.
     */
    @Deprecated(
        "Use Crc.crc32b from cryptohash-crc",
        ReplaceWith("Crc.crc32b", "com.appmattus.crypto.Crc")
    )
    public data object CRC32B : Algorithm("CRC32B", 32)

    /**
     * [Crc](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) with output size of 32 bits.
     * Castagnoli's CRC, used by iSCSI, SCTP, Btrfs, ext4, etc.
     */
    @Deprecated(
        "Use Crc.crc32c from cryptohash-crc",
        ReplaceWith("Crc.crc32c", "com.appmattus.crypto.Crc")
    )
    public data object CRC32C : Algorithm("CRC32C", 32)

    /**
     * [cSHAKE](https://keccak.team/keccak.html) with output size of 128 bits
     */
    @Deprecated("Use Sp800185.cshake128 from cryptohash-keccak")
    public class cSHAKE128(
        customisation: ByteArray? = null,
        functionName: ByteArray? = null
    ) : Algorithm("cSHAKE128", 168) {
        internal val customisation: ByteArray? = customisation?.copyOf()
        internal val functionName: ByteArray? = functionName?.copyOf()
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("customisation" to customisation, "functionName" to functionName)
    }

    /**
     * [cSHAKE](https://keccak.team/keccak.html) with output size of 256 bits
     */
    @Deprecated("Use Sp800185.cshake256 from cryptohash-keccak")
    public class cSHAKE256(
        customisation: ByteArray? = null,
        functionName: ByteArray? = null
    ) : Algorithm("cSHAKE256", 136) {
        internal val customisation: ByteArray? = customisation?.copyOf()
        internal val functionName: ByteArray? = functionName?.copyOf()
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("customisation" to customisation, "functionName" to functionName)
    }

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 224 bits
     */
    @Deprecated(
        "Use CubeHash.cubeHash224 from cryptohash-cubehash",
        ReplaceWith("CubeHash.cubeHash224", "com.appmattus.crypto.CubeHash")
    )
    public data object CubeHash224 : Algorithm("CubeHash-224", 32)

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 256 bits
     */
    @Deprecated(
        "Use CubeHash.cubeHash256 from cryptohash-cubehash",
        ReplaceWith("CubeHash.cubeHash256", "com.appmattus.crypto.CubeHash")
    )
    public data object CubeHash256 : Algorithm("CubeHash-256", 32)

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 384 bits
     */
    @Deprecated(
        "Use CubeHash.cubeHash384 from cryptohash-cubehash",
        ReplaceWith("CubeHash.cubeHash384", "com.appmattus.crypto.CubeHash")
    )
    public data object CubeHash384 : Algorithm("CubeHash-384", 32)

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 512 bits
     */
    @Deprecated(
        "Use CubeHash.cubeHash512 from cryptohash-cubehash",
        ReplaceWith("CubeHash.cubeHash512", "com.appmattus.crypto.CubeHash")
    )
    public data object CubeHash512 : Algorithm("CubeHash-512", 32)

    /**
     * [Echo](https://crypto.orange-labs.fr/ECHO/) with output size 224 bits
     */
    @Deprecated(
        "Use Echo.echo224 from cryptohash-echo",
        ReplaceWith("Echo.echo224", "com.appmattus.crypto.Echo")
    )
    public data object ECHO224 : Algorithm("ECHO-224", 192)

    /**
     * [Echo](https://crypto.orange-labs.fr/ECHO/) with output size 256 bits
     */
    @Deprecated(
        "Use Echo.echo256 from cryptohash-echo",
        ReplaceWith("Echo.echo256", "com.appmattus.crypto.Echo")
    )
    public data object ECHO256 : Algorithm("ECHO-256", 192)

    /**
     * [Echo](https://crypto.orange-labs.fr/ECHO/) with output size 384 bits
     */
    @Deprecated(
        "Use Echo.echo384 from cryptohash-echo",
        ReplaceWith("Echo.echo384", "com.appmattus.crypto.Echo")
    )
    public data object ECHO384 : Algorithm("ECHO-384", 128)

    /**
     * [Echo](https://crypto.orange-labs.fr/ECHO/) with output size 512 bits
     */
    @Deprecated(
        "Use Echo.echo512 from cryptohash-echo",
        ReplaceWith("Echo.echo512", "com.appmattus.crypto.Echo")
    )
    public data object ECHO512 : Algorithm("ECHO-512", 128)

    /**
     * [FarmHash](https://github.com/google/farmhash) with output size of 32 bits
     */
    @Deprecated("Use FarmHash.farmHash32 from cryptohash-cityhash")
    public open class FarmHash32 : Algorithm("FarmHash32", 4) {
        /**
         * [FarmHash32] using [seed] with output size of 64 bits
         */
        public class Seed(internal val seed: UInt) : FarmHash32() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seed" to seed)
        }
    }

    /**
     * [FarmHash](https://github.com/google/farmhash) with output size of 64 bits
     */
    @Deprecated("Use FarmHash.farmHash64 from cryptohash-cityhash")
    public open class FarmHash64 : Algorithm("FarmHash64", 8) {
        /**
         * [FarmHash64] using [seed] with output size of 64 bits
         */
        public class Seed(internal val seed: ULong) : FarmHash64() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seed" to seed)
        }

        /**
         * [FarmHash64] using [seed1] and [seed2] with output size of 64 bits
         */
        public class Seeds(internal val seed1: ULong, internal val seed2: ULong) : FarmHash64() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seed1" to seed1, "seed2" to seed2)
        }
    }

    /**
     * [FarmHash](https://github.com/google/farmhash) with output size of 128 bits
     */
    @Deprecated("Use FarmHash.farmHash128 from cryptohash-cityhash")
    public open class FarmHash128 : Algorithm("FarmHash128", 16) {
        /**
         * [FarmHash128] using seed ([seedLow] & [seedHigh]) with output size of 128 bits
         */
        public class Seed(internal val seedLow: ULong, internal val seedHigh: ULong) : FarmHash128() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seedLow" to seedLow, "seedHigh" to seedHigh)
        }
    }

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 224 bits
     */
    @Deprecated(
        "Use Fugue.fugue224 from cryptohash-fugue",
        ReplaceWith("Fugue.fugue224", "com.appmattus.crypto.Fugue")
    )
    public data object Fugue224 : Algorithm("Fugue-224", 28)

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 256 bits
     */
    @Deprecated(
        "Use Fugue.fugue256 from cryptohash-fugue",
        ReplaceWith("Fugue.fugue256", "com.appmattus.crypto.Fugue")
    )
    public data object Fugue256 : Algorithm("Fugue-256", 32)

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 384 bits
     */
    @Deprecated(
        "Use Fugue.fugue384 from cryptohash-fugue",
        ReplaceWith("Fugue.fugue384", "com.appmattus.crypto.Fugue")
    )
    public data object Fugue384 : Algorithm("Fugue-384", 48)

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 512 bits
     */
    @Deprecated(
        "Use Fugue.fugue512 from cryptohash-fugue",
        ReplaceWith("Fugue.fugue512", "com.appmattus.crypto.Fugue")
    )
    public data object Fugue512 : Algorithm("Fugue-512", 64)

    /**
     * [GOST R 34.11-94](https://en.wikipedia.org/wiki/GOST_(hash_function)) with output size 256 bits
     */
    @Deprecated(
        "Use Gost.gost3411_94 from cryptohash-gost",
        ReplaceWith("Gost.gost3411_94", "com.appmattus.crypto.Gost")
    )
    public data object GOST3411_94 : Algorithm("GOST3411", 32), Hmac

    /**
     * [GOST R 34.11-2012](https://en.wikipedia.org/wiki/GOST_(hash_function)) with output size 256 bits
     */
    @Deprecated(
        "Use Streebog.streebog256 from cryptohash-streebog",
        ReplaceWith("Streebog.streebog256", "com.appmattus.crypto.Streebog")
    )
    public data object GOST3411_2012_256 : Algorithm("GOST3411-2012-256", 64), Hmac

    /**
     * [GOST R 34.11-2012](https://en.wikipedia.org/wiki/GOST_(hash_function)) with output size 512 bits
     */
    @Deprecated(
        "Use Streebog.streebog512 from cryptohash-streebog",
        ReplaceWith("Streebog.streebog512", "com.appmattus.crypto.Streebog")
    )
    public data object GOST3411_2012_512 : Algorithm("GOST3411-2012-512", 64), Hmac

    /**
     * [Grøstl](https://www.groestl.info) with output size 224 bits
     */
    @Deprecated(
        "Use Groestl.groestl224 from cryptohash-groestl",
        ReplaceWith("Groestl.groestl224", "com.appmattus.crypto.Groestl")
    )
    public data object Groestl224 : Algorithm("Groestl-224", 64)

    /**
     * [Grøstl](https://www.groestl.info) with output size 256 bits
     */
    @Deprecated(
        "Use Groestl.groestl256 from cryptohash-groestl",
        ReplaceWith("Groestl.groestl256", "com.appmattus.crypto.Groestl")
    )
    public data object Groestl256 : Algorithm("Groestl-256", 64)

    /**
     * [Grøstl](https://www.groestl.info) with output size 384 bits
     */
    @Deprecated(
        "Use Groestl.groestl384 from cryptohash-groestl",
        ReplaceWith("Groestl.groestl384", "com.appmattus.crypto.Groestl")
    )
    public data object Groestl384 : Algorithm("Groestl-384", 128)

    /**
     * [Grøstl](https://www.groestl.info) with output size 512 bits
     */
    @Deprecated(
        "Use Groestl.groestl512 from cryptohash-groestl",
        ReplaceWith("Groestl.groestl512", "com.appmattus.crypto.Groestl")
    )
    public data object Groestl512 : Algorithm("Groestl-512", 128)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 224 bits
     */
    @Deprecated(
        "Use Hamsi.hamsi224 from cryptohash-hamsi",
        ReplaceWith("Hamsi.hamsi224", "com.appmattus.crypto.Hamsi")
    )
    public data object Hamsi224 : Algorithm("Hamsi-224", 32)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 256 bits
     */
    @Deprecated(
        "Use Hamsi.hamsi256 from cryptohash-hamsi",
        ReplaceWith("Hamsi.hamsi256", "com.appmattus.crypto.Hamsi")
    )
    public data object Hamsi256 : Algorithm("Hamsi-256", 32)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 384 bits
     */
    @Deprecated(
        "Use Hamsi.hamsi384 from cryptohash-hamsi",
        ReplaceWith("Hamsi.hamsi384", "com.appmattus.crypto.Hamsi")
    )
    public data object Hamsi384 : Algorithm("Hamsi-384", 32)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 512 bits
     */
    @Deprecated(
        "Use Hamsi.hamsi512 from cryptohash-hamsi",
        ReplaceWith("Hamsi.hamsi512", "com.appmattus.crypto.Hamsi")
    )
    public data object Hamsi512 : Algorithm("Hamsi-512", 32)

    /**
     * [Haraka v2](https://github.com/kste/haraka) with output size 256 bits
     */
    @Deprecated(
        "Use Haraka.haraka256 from cryptohash-haraka",
        ReplaceWith("Haraka.haraka256", "com.appmattus.crypto.Haraka")
    )
    public data object Haraka256_256 : Algorithm("Haraka-256", 32)

    /**
     * [Haraka v2](https://github.com/kste/haraka) with output size 256 bits
     */
    @Deprecated(
        "Use Haraka.haraka512 from cryptohash-haraka",
        ReplaceWith("Haraka.haraka512", "com.appmattus.crypto.Haraka")
    )
    public data object Haraka512_256 : Algorithm("Haraka-512", 64)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 128 bits
     */
    @Deprecated(
        "Use Haval.haval3_128 from cryptohash-haval",
        ReplaceWith("Haval.haval3_128", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_3_128 : Algorithm("HAVAL-3-128", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 160 bits
     */
    @Deprecated(
        "Use Haval.haval3_160 from cryptohash-haval",
        ReplaceWith("Haval.haval3_160", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_3_160 : Algorithm("HAVAL-3-160", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 192 bits
     */
    @Deprecated(
        "Use Haval.haval3_192 from cryptohash-haval",
        ReplaceWith("Haval.haval3_192", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_3_192 : Algorithm("HAVAL-3-192", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 224 bits
     */
    @Deprecated(
        "Use Haval.haval3_224 from cryptohash-haval",
        ReplaceWith("Haval.haval3_224", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_3_224 : Algorithm("HAVAL-3-224", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 256 bits
     */
    @Deprecated(
        "Use Haval.haval3_256 from cryptohash-haval",
        ReplaceWith("Haval.haval3_256", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_3_256 : Algorithm("HAVAL-3-256", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 128 bits
     */
    @Deprecated(
        "Use Haval.haval4_128 from cryptohash-haval",
        ReplaceWith("Haval.haval4_128", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_4_128 : Algorithm("HAVAL-4-128", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 160 bits
     */
    @Deprecated(
        "Use Haval.haval4_160 from cryptohash-haval",
        ReplaceWith("Haval.haval4_160", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_4_160 : Algorithm("HAVAL-4-160", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 192 bits
     */
    @Deprecated(
        "Use Haval.haval4_192 from cryptohash-haval",
        ReplaceWith("Haval.haval4_192", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_4_192 : Algorithm("HAVAL-4-192", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 224 bits
     */
    @Deprecated(
        "Use Haval.haval4_224 from cryptohash-haval",
        ReplaceWith("Haval.haval4_224", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_4_224 : Algorithm("HAVAL-4-224", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 256 bits
     */
    @Deprecated(
        "Use Haval.haval4_256 from cryptohash-haval",
        ReplaceWith("Haval.haval4_256", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_4_256 : Algorithm("HAVAL-4-256", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 128 bits
     */
    @Deprecated(
        "Use Haval.haval5_128 from cryptohash-haval",
        ReplaceWith("Haval.haval5_128", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_5_128 : Algorithm("HAVAL-5-128", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 160 bits
     */
    @Deprecated(
        "Use Haval.haval5_160 from cryptohash-haval",
        ReplaceWith("Haval.haval5_160", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_5_160 : Algorithm("HAVAL-5-160", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 192 bits
     */
    @Deprecated(
        "Use Haval.haval5_192 from cryptohash-haval",
        ReplaceWith("Haval.haval5_192", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_5_192 : Algorithm("HAVAL-5-192", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 224 bits
     */
    @Deprecated(
        "Use Haval.haval5_224 from cryptohash-haval",
        ReplaceWith("Haval.haval5_224", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_5_224 : Algorithm("HAVAL-5-224", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 256 bits
     */
    @Deprecated(
        "Use Haval.haval5_256 from cryptohash-haval",
        ReplaceWith("Haval.haval5_256", "com.appmattus.crypto.Haval")
    )
    public data object HAVAL_5_256 : Algorithm("HAVAL-5-256", 128)

    /**
     * [HighwayHash](https://github.com/google/highwayhash) with output size 64 bits
     */
    @Deprecated("Use HighwayHash.highwayHash64 from cryptohash-highwayhash")
    public class HighwayHash64(
        key: LongArray
    ) : Algorithm("HighwayHash-64", 32) {
        internal val key: LongArray = key.copyOf()

        init {
            require(key.size == HIGHWAY_HASH_KEY_SIZE) { "key must be exactly $HIGHWAY_HASH_KEY_SIZE longs, was ${key.size}" }
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("key" to key)
    }

    /**
     * [HighwayHash](https://github.com/google/highwayhash) with output size 128 bits
     */
    @Deprecated("Use HighwayHash.highwayHash128 from cryptohash-highwayhash")
    public class HighwayHash128(
        key: LongArray
    ) : Algorithm("HighwayHash-128", 32) {
        internal val key: LongArray = key.copyOf()

        init {
            require(key.size == HIGHWAY_HASH_KEY_SIZE) { "key must be exactly $HIGHWAY_HASH_KEY_SIZE longs, was ${key.size}" }
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("key" to key)
    }

    /**
     * [HighwayHash](https://github.com/google/highwayhash) with output size 256 bits
     */
    @Deprecated("Use HighwayHash.highwayHash256 from cryptohash-highwayhash")
    public class HighwayHash256(
        key: LongArray
    ) : Algorithm("HighwayHash-256", 32) {
        internal val key: LongArray = key.copyOf()

        init {
            require(key.size == HIGHWAY_HASH_KEY_SIZE) { "key must be exactly $HIGHWAY_HASH_KEY_SIZE longs, was ${key.size}" }
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("key" to key)
    }

    /**
     * [Jh](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 224 bits
     */
    @Deprecated(
        "Use Jh.jh224 from cryptohash-jh",
        ReplaceWith("Jh.jh224", "com.appmattus.crypto.Jh")
    )
    public data object JH224 : Algorithm("JH-224", 64)

    /**
     * [Jh](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 256 bits
     */
    @Deprecated(
        "Use Jh.jh256 from cryptohash-jh",
        ReplaceWith("Jh.jh256", "com.appmattus.crypto.Jh")
    )
    public data object JH256 : Algorithm("JH-256", 64)

    /**
     * [Jh](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 384 bits
     */
    @Deprecated(
        "Use Jh.jh384 from cryptohash-jh",
        ReplaceWith("Jh.jh384", "com.appmattus.crypto.Jh")
    )
    public data object JH384 : Algorithm("JH-384", 64)

    /**
     * [Jh](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 512 bits
     */
    @Deprecated(
        "Use Jh.jh512 from cryptohash-jh",
        ReplaceWith("Jh.jh512", "com.appmattus.crypto.Jh")
    )
    public data object JH512 : Algorithm("JH-512", 64)

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 224 bits
     */
    @Deprecated(
        "Use Keccak.keccak224 from cryptohash-keccak",
        ReplaceWith("Keccak.keccak224", "com.appmattus.crypto.Keccak")
    )
    public data object Keccak224 : Algorithm("Keccak-224", 144), Hmac

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 256 bits
     */
    @Deprecated(
        "Use Keccak.keccak256 from cryptohash-keccak",
        ReplaceWith("Keccak.keccak256", "com.appmattus.crypto.Keccak")
    )
    public data object Keccak256 : Algorithm("Keccak-256", 136), Hmac

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 288 bits
     */
    @Deprecated(
        "Use Keccak.keccak288 from cryptohash-keccak",
        ReplaceWith("Keccak.keccak288", "com.appmattus.crypto.Keccak")
    )
    public data object Keccak288 : Algorithm("Keccak-288", 128), Hmac

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 384 bits
     */
    @Deprecated(
        "Use Keccak.keccak384 from cryptohash-keccak",
        ReplaceWith("Keccak.keccak384", "com.appmattus.crypto.Keccak")
    )
    public data object Keccak384 : Algorithm("Keccak-384", 104), Hmac

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 512 bits
     */
    @Deprecated(
        "Use Keccak.keccak512 from cryptohash-keccak",
        ReplaceWith("Keccak.keccak512", "com.appmattus.crypto.Keccak")
    )
    public data object Keccak512 : Algorithm("Keccak-512", 72), Hmac

    /**
     * [KMAC128](https://doi.org/10.6028/NIST.SP.800-185), the Keccak message authentication code from NIST SP 800-185,
     * keyed with [key] and with output size of [outputSizeBits] bits (default: 256 bits).
     * An optional [customisation] string separates uses of the same key.
     */
    @Deprecated("Use Sp800185.kmac128 from cryptohash-keccak")
    public class KMAC128(
        key: ByteArray,
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 256
    ) : Algorithm("KMAC128", 168) {
        internal val key: ByteArray = key.copyOf()
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("key" to key, "customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [KMAC256](https://doi.org/10.6028/NIST.SP.800-185), the Keccak message authentication code from NIST SP 800-185,
     * keyed with [key] and with output size of [outputSizeBits] bits (default: 512 bits).
     * An optional [customisation] string separates uses of the same key.
     */
    @Deprecated("Use Sp800185.kmac256 from cryptohash-keccak")
    public class KMAC256(
        key: ByteArray,
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 512
    ) : Algorithm("KMAC256", 136) {
        internal val key: ByteArray = key.copyOf()
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("key" to key, "customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [komihash](https://github.com/avaneev/komihash) with output size of 64 bits
     */
    @Deprecated("Use Komihash.komihash from cryptohash-komihash")
    public class Komihash(internal val seed: ULong = 0u) : Algorithm("komihash", 64) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [Kupyna (aka DSTU7564)](https://en.wikipedia.org/wiki/Kupyna) with output size 256 bits
     */
    @Deprecated(
        "Use Kupyna.kupyna256 from cryptohash-kupyna",
        ReplaceWith("Kupyna.kupyna256", "com.appmattus.crypto.Kupyna")
    )
    public data object Kupyna_256 : Algorithm("Kupyna-256", 64)

    /**
     * [Kupyna (aka DSTU7564)](https://en.wikipedia.org/wiki/Kupyna) with output size 384 bits
     */
    @Deprecated(
        "Use Kupyna.kupyna384 from cryptohash-kupyna",
        ReplaceWith("Kupyna.kupyna384", "com.appmattus.crypto.Kupyna")
    )
    public data object Kupyna_384 : Algorithm("Kupyna-384", 128)

    /**
     * [Kupyna (aka DSTU7564)](https://en.wikipedia.org/wiki/Kupyna) with output size 512 bits
     */
    @Deprecated(
        "Use Kupyna.kupyna512 from cryptohash-kupyna",
        ReplaceWith("Kupyna.kupyna512", "com.appmattus.crypto.Kupyna")
    )
    public data object Kupyna_512 : Algorithm("Kupyna-512", 128)

    /**
     * [KT128](https://www.rfc-editor.org/rfc/rfc9861), the KangarooTwelve tree hash from RFC 9861, with output
     * size of [outputSizeBits] bits (default: 256 bits) and an optional [customisation] string.
     */
    @Deprecated("Use KangarooTwelve.kt128 from cryptohash-keccak")
    public class KT128(
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 256
    ) : Algorithm("KT128", 168) {
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [KT256](https://www.rfc-editor.org/rfc/rfc9861), the KangarooTwelve tree hash from RFC 9861, with output
     * size of [outputSizeBits] bits (default: 512 bits) and an optional [customisation] string.
     */
    @Deprecated("Use KangarooTwelve.kt256 from cryptohash-keccak")
    public class KT256(
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 512
    ) : Algorithm("KT256", 136) {
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 224 bits
     */
    @Deprecated(
        "Use Luffa.luffa224 from cryptohash-luffa",
        ReplaceWith("Luffa.luffa224", "com.appmattus.crypto.Luffa")
    )
    public data object Luffa224 : Algorithm("Luffa-224", 32)

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 256 bits
     */
    @Deprecated(
        "Use Luffa.luffa256 from cryptohash-luffa",
        ReplaceWith("Luffa.luffa256", "com.appmattus.crypto.Luffa")
    )
    public data object Luffa256 : Algorithm("Luffa-256", 32)

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 384 bits
     */
    @Deprecated(
        "Use Luffa.luffa384 from cryptohash-luffa",
        ReplaceWith("Luffa.luffa384", "com.appmattus.crypto.Luffa")
    )
    public data object Luffa384 : Algorithm("Luffa-384", 32)

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 512 bits
     */
    @Deprecated(
        "Use Luffa.luffa512 from cryptohash-luffa",
        ReplaceWith("Luffa.luffa512", "com.appmattus.crypto.Luffa")
    )
    public data object Luffa512 : Algorithm("Luffa-512", 32)

    /**
     * [MetroHash](https://github.com/jandrewrogers/MetroHash) with output size of 64 bits
     */
    public data class MetroHash64(val seed: ULong = 0u) : Algorithm("MetroHash64", 32)

    /**
     * [MetroHash](https://github.com/jandrewrogers/MetroHash) with output size of 128 bits
     */
    public data class MetroHash128(val seed: ULong = 0u) : Algorithm("MetroHash128", 32)

    /**
     * [MD2](https://en.wikipedia.org/wiki/MD2_(hash_function)) with output size of 128 bits
     */
    @Deprecated(
        "Use Md.md2 from cryptohash-md",
        ReplaceWith("Md.md2", "com.appmattus.crypto.Md")
    )
    public data object MD2 : Algorithm("MD2", 16), Hmac

    /**
     * [MD4](https://en.wikipedia.org/wiki/MD4) with output size of 128 bits
     */
    @Deprecated(
        "Use Md.md4 from cryptohash-md",
        ReplaceWith("Md.md4", "com.appmattus.crypto.Md")
    )
    public data object MD4 : Algorithm("MD4", 64), Hmac

    /**
     * [MD5](https://en.wikipedia.org/wiki/MD5) with output size of 128 bits
     */
    @Deprecated(
        "Use Md.md5 from cryptohash-md",
        ReplaceWith("Md.md5", "com.appmattus.crypto.Md")
    )
    public data object MD5 : Algorithm("MD5", 64), Hmac

    /**
     * [MurmurHash1](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1.cpp) for x86 platform with output size of 32 bits
     */
    public data class MurmurHash1(val seed: UInt = 0u) : Algorithm("MurmurHash1", 4)

    /**
     * [MurmurHash2](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x86 platform with output size of 32 bits
     * The algorithm is non-incremental in nature so calling update adds the data to an internal buffer.
     */
    public data class MurmurHash2(val seed: UInt = 0u) : Algorithm("MurmurHash2", 4)

    /**
     * [MurmurHash64A](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x64 platform with output size of 64 bits
     * The algorithm is non-incremental in nature so calling update adds the data to an internal buffer.
     */
    public data class MurmurHash64A(val seed: ULong = 0u) : Algorithm("MurmurHash64A", 8)

    /**
     * [MurmurHash64B](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x86 platform with output size of 64 bits
     * The algorithm is non-incremental in nature so calling update adds the data to an internal buffer.
     */
    public data class MurmurHash64B(val seed: ULong = 0u) : Algorithm("MurmurHash64B", 8)

    /**
     * [MurmurHash2A](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp) for x86 platform with output size of 32 bits
     */
    public data class MurmurHash2A(val seed: UInt = 0u) : Algorithm("MurmurHash2A", 4)

    /**
     * [MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x86 platform with output size of 32 bits
     */
    public data class MurmurHash3_X86_32(val seed: UInt = 0u) : Algorithm("MurmurHash3-x86-32", 4)

    /**
     * [MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x86 platform with output size of 128 bits
     */
    public data class MurmurHash3_X86_128(val seed: UInt = 0u) : Algorithm("MurmurHash3-x86-128", 16)

    /**
     * [MurmurHash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) for x64 platform with output size of 128 bits
     */
    public data class MurmurHash3_X64_128(val seed: UInt = 0u) : Algorithm("MurmurHash3-x64-128", 16)

    /**
     * [Panama](https://en.wikipedia.org/wiki/Panama_(cryptography)) with output size of 256 bits
     */
    @Deprecated(
        "Use Panama.panama from cryptohash-panama",
        ReplaceWith("Panama.panama", "com.appmattus.crypto.Panama")
    )
    public data object PANAMA : Algorithm("PANAMA", 32)

    /**
     * [ParallelHash128](https://doi.org/10.6028/NIST.SP.800-185) from NIST SP 800-185, which hashes the input in
     * independent blocks of [blockSize] bytes, with output size of [outputSizeBits] bits (default: 256 bits) and
     * an optional [customisation] string.
     */
    @Deprecated("Use Sp800185.parallelHash128 from cryptohash-keccak")
    public class ParallelHash128(
        internal val blockSize: Int,
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 256
    ) : Algorithm("ParallelHash128", 168) {
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            require(blockSize > 0) { "blockSize must be greater than 0, was $blockSize" }
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("blockSize" to blockSize, "customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [ParallelHash256](https://doi.org/10.6028/NIST.SP.800-185) from NIST SP 800-185, which hashes the input in
     * independent blocks of [blockSize] bytes, with output size of [outputSizeBits] bits (default: 512 bits) and
     * an optional [customisation] string.
     */
    @Deprecated("Use Sp800185.parallelHash256 from cryptohash-keccak")
    public class ParallelHash256(
        internal val blockSize: Int,
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 512
    ) : Algorithm("ParallelHash256", 136) {
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            require(blockSize > 0) { "blockSize must be greater than 0, was $blockSize" }
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("blockSize" to blockSize, "customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [RadioGatún](https://en.wikipedia.org/wiki/RadioGatún) with 32-bit word width and output size of 256 bits
     */
    @Deprecated(
        "Use RadioGatun.radioGatun32 from cryptohash-radiogatun",
        ReplaceWith("RadioGatun.radioGatun32", "com.appmattus.crypto.RadioGatun")
    )
    public data object RadioGatun32 : Algorithm("RadioGatún[32]", 156)

    /**
     * [RadioGatún](https://en.wikipedia.org/wiki/RadioGatún) with 64-bit word width and output size of 256 bits
     */
    @Deprecated(
        "Use RadioGatun.radioGatun64 from cryptohash-radiogatun",
        ReplaceWith("RadioGatun.radioGatun64", "com.appmattus.crypto.RadioGatun")
    )
    public data object RadioGatun64 : Algorithm("RadioGatún[64]", 312)

    /**
     * [rapidhash](https://github.com/Nicoshev/rapidhash) V3 with output size of 64 bits
     */
    @Deprecated("Use Rapidhash.rapidhash from cryptohash-rapidhash")
    public class Rapidhash(internal val seed: ULong = 0u) : Algorithm("rapidhash", 112) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [rapidhashMicro](https://github.com/Nicoshev/rapidhash), the rapidhash V3 variant tuned for smaller code size,
     * with output size of 64 bits
     */
    @Deprecated("Use Rapidhash.rapidhashMicro from cryptohash-rapidhash")
    public class RapidhashMicro(internal val seed: ULong = 0u) : Algorithm("rapidhashMicro", 80) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [rapidhashNano](https://github.com/Nicoshev/rapidhash), the rapidhash V3 variant tuned for the smallest code
     * size, with output size of 64 bits
     */
    @Deprecated("Use Rapidhash.rapidhashNano from cryptohash-rapidhash")
    public class RapidhashNano(internal val seed: ULong = 0u) : Algorithm("rapidhashNano", 48) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * Original [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 128 bits
     */
    @Deprecated(
        "Use RipeMd.ripeMd from cryptohash-ripemd",
        ReplaceWith("RipeMd.ripeMd", "com.appmattus.crypto.RipeMd")
    )
    public data object RipeMD : Algorithm("RipeMD", 64)

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 128 bits
     */
    @Deprecated(
        "Use RipeMd.ripeMd128 from cryptohash-ripemd",
        ReplaceWith("RipeMd.ripeMd128", "com.appmattus.crypto.RipeMd")
    )
    public data object RipeMD128 : Algorithm("RipeMD128", 64), Hmac

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 160 bits
     */
    @Deprecated(
        "Use RipeMd.ripeMd160 from cryptohash-ripemd",
        ReplaceWith("RipeMd.ripeMd160", "com.appmattus.crypto.RipeMd")
    )
    public data object RipeMD160 : Algorithm("RipeMD160", 64), Hmac

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 256 bits
     */
    @Deprecated(
        "Use RipeMd.ripeMd256 from cryptohash-ripemd",
        ReplaceWith("RipeMd.ripeMd256", "com.appmattus.crypto.RipeMd")
    )
    public data object RipeMD256 : Algorithm("RipeMD256", 64), Hmac

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 320 bits
     */
    @Deprecated(
        "Use RipeMd.ripeMd320 from cryptohash-ripemd",
        ReplaceWith("RipeMd.ripeMd320", "com.appmattus.crypto.RipeMd")
    )
    public data object RipeMD320 : Algorithm("RipeMD320", 64), Hmac

    /**
     * [SHA-0](https://en.wikipedia.org/wiki/SHA-1#Development) with output size of 160 bits
     */
    @Deprecated(
        "Use Sha1.sha0 from cryptohash-sha1",
        ReplaceWith("Sha1.sha0", "com.appmattus.crypto.Sha1")
    )
    public data object SHA_0 : Algorithm("SHA-0", 64), Hmac

    /**
     * [SHA-1](https://en.wikipedia.org/wiki/SHA-1) with output size of 160 bits
     */
    @Deprecated(
        "Use Sha1.sha1 from cryptohash-sha1",
        ReplaceWith("Sha1.sha1", "com.appmattus.crypto.Sha1")
    )
    public data object SHA_1 : Algorithm("SHA-1", 64), Hmac

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 224 bits
     */
    @Deprecated(
        "Use Sha2.sha224 from cryptohash-sha2",
        ReplaceWith("Sha2.sha224", "com.appmattus.crypto.Sha2")
    )
    public data object SHA_224 : Algorithm("SHA-224", 64), Hmac

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 256 bits
     */
    @Deprecated(
        "Use Sha2.sha256 from cryptohash-sha2",
        ReplaceWith("Sha2.sha256", "com.appmattus.crypto.Sha2")
    )
    public data object SHA_256 : Algorithm("SHA-256", 64), Hmac

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 384 bits
     */
    @Deprecated(
        "Use Sha2.sha384 from cryptohash-sha2",
        ReplaceWith("Sha2.sha384", "com.appmattus.crypto.Sha2")
    )
    public data object SHA_384 : Algorithm("SHA-384", 128), Hmac

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 512 bits
     */
    @Deprecated(
        "Use Sha2.sha512 from cryptohash-sha2",
        ReplaceWith("Sha2.sha512", "com.appmattus.crypto.Sha2")
    )
    public data object SHA_512 : Algorithm("SHA-512", 128), Hmac

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 224 bits
     */
    @Deprecated(
        "Use Sha2.sha512_224 from cryptohash-sha2",
        ReplaceWith("Sha2.sha512_224", "com.appmattus.crypto.Sha2")
    )
    public data object SHA_512_224 : Algorithm("SHA-512/224", 128), Hmac

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 256 bits
     */
    @Deprecated(
        "Use Sha2.sha512_256 from cryptohash-sha2",
        ReplaceWith("Sha2.sha512_256", "com.appmattus.crypto.Sha2")
    )
    public data object SHA_512_256 : Algorithm("SHA-512/256", 128), Hmac

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 224 bits
     */
    @Deprecated(
        "Use Sha3.sha3_224 from cryptohash-keccak",
        ReplaceWith("Sha3.sha3_224", "com.appmattus.crypto.Sha3")
    )
    public data object SHA3_224 : Algorithm("SHA3-224", 144), Hmac

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 256 bits
     */
    @Deprecated(
        "Use Sha3.sha3_256 from cryptohash-keccak",
        ReplaceWith("Sha3.sha3_256", "com.appmattus.crypto.Sha3")
    )
    public data object SHA3_256 : Algorithm("SHA3-256", 136), Hmac

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 384 bits
     */
    @Deprecated(
        "Use Sha3.sha3_384 from cryptohash-keccak",
        ReplaceWith("Sha3.sha3_384", "com.appmattus.crypto.Sha3")
    )
    public data object SHA3_384 : Algorithm("SHA3-384", 104), Hmac

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 512 bits
     */
    @Deprecated(
        "Use Sha3.sha3_512 from cryptohash-keccak",
        ReplaceWith("Sha3.sha3_512", "com.appmattus.crypto.Sha3")
    )
    public data object SHA3_512 : Algorithm("SHA3-512", 72), Hmac

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 192 bits
     */
    @Deprecated(
        "Use Shabal.shabal192 from cryptohash-shabal",
        ReplaceWith("Shabal.shabal192", "com.appmattus.crypto.Shabal")
    )
    public data object Shabal192 : Algorithm("Shabal-192", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 224 bits
     */
    @Deprecated(
        "Use Shabal.shabal224 from cryptohash-shabal",
        ReplaceWith("Shabal.shabal224", "com.appmattus.crypto.Shabal")
    )
    public data object Shabal224 : Algorithm("Shabal-224", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 256 bits
     */
    @Deprecated(
        "Use Shabal.shabal256 from cryptohash-shabal",
        ReplaceWith("Shabal.shabal256", "com.appmattus.crypto.Shabal")
    )
    public data object Shabal256 : Algorithm("Shabal-256", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 384 bits
     */
    @Deprecated(
        "Use Shabal.shabal384 from cryptohash-shabal",
        ReplaceWith("Shabal.shabal384", "com.appmattus.crypto.Shabal")
    )
    public data object Shabal384 : Algorithm("Shabal-384", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 512 bits
     */
    @Deprecated(
        "Use Shabal.shabal512 from cryptohash-shabal",
        ReplaceWith("Shabal.shabal512", "com.appmattus.crypto.Shabal")
    )
    public data object Shabal512 : Algorithm("Shabal-512", 64)

    /**
     * [SHAKE](https://keccak.team/keccak.html) with output size of 128 bits
     */
    @Deprecated(
        "Use Sha3.shake128 from cryptohash-keccak",
        ReplaceWith("Sha3.shake128", "com.appmattus.crypto.Sha3")
    )
    public data object SHAKE128 : Algorithm("SHAKE128", 168)

    /**
     * [SHAKE](https://keccak.team/keccak.html) with output size of 256 bits
     */
    @Deprecated(
        "Use Sha3.shake256 from cryptohash-keccak",
        ReplaceWith("Sha3.shake256", "com.appmattus.crypto.Sha3")
    )
    public data object SHAKE256 : Algorithm("SHAKE256", 136)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 224 bits
     */
    @Deprecated(
        "Use Shavite.shavite224 from cryptohash-shavite",
        ReplaceWith("Shavite.shavite224", "com.appmattus.crypto.Shavite")
    )
    public data object SHAvite224 : Algorithm("SHAvite-224", 64)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 256 bits
     */
    @Deprecated(
        "Use Shavite.shavite256 from cryptohash-shavite",
        ReplaceWith("Shavite.shavite256", "com.appmattus.crypto.Shavite")
    )
    public data object SHAvite256 : Algorithm("SHAvite-256", 64)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 384 bits
     */
    @Deprecated(
        "Use Shavite.shavite384 from cryptohash-shavite",
        ReplaceWith("Shavite.shavite384", "com.appmattus.crypto.Shavite")
    )
    public data object SHAvite384 : Algorithm("SHAvite-384", 128)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 512 bits
     */
    @Deprecated(
        "Use Shavite.shavite512 from cryptohash-shavite",
        ReplaceWith("Shavite.shavite512", "com.appmattus.crypto.Shavite")
    )
    public data object SHAvite512 : Algorithm("SHAvite-512", 128)

    /**
     * [Simd](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 224 bits
     */
    @Deprecated(
        "Use Simd.simd224 from cryptohash-simd",
        ReplaceWith("Simd.simd224", "com.appmattus.crypto.Simd")
    )
    public data object SIMD224 : Algorithm("SIMD-224", 64)

    /**
     * [Simd](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 256 bits
     */
    @Deprecated(
        "Use Simd.simd256 from cryptohash-simd",
        ReplaceWith("Simd.simd256", "com.appmattus.crypto.Simd")
    )
    public data object SIMD256 : Algorithm("SIMD-256", 64)

    /**
     * [Simd](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 384 bits
     */
    @Deprecated(
        "Use Simd.simd384 from cryptohash-simd",
        ReplaceWith("Simd.simd384", "com.appmattus.crypto.Simd")
    )
    public data object SIMD384 : Algorithm("SIMD-384", 128)

    /**
     * [Simd](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 512 bits
     */
    @Deprecated(
        "Use Simd.simd512 from cryptohash-simd",
        ReplaceWith("Simd.simd512", "com.appmattus.crypto.Simd")
    )
    public data object SIMD512 : Algorithm("SIMD-512", 128)

    /**
     * [SipHash](https://www.aumasson.jp/siphash/siphash.pdf), a keyed pseudorandom function with output size of 64 bits,
     * using a 16 byte [key], [compressionRounds] compression rounds and [finalizationRounds] finalization rounds
     * (default: SipHash-2-4)
     */
    @Deprecated("Use SipHash.sipHash from cryptohash-siphash")
    public class SipHash(
        key: ByteArray,
        internal val compressionRounds: Int = 2,
        internal val finalizationRounds: Int = 4
    ) : Algorithm("SipHash-$compressionRounds-$finalizationRounds", 8) {
        internal val key: ByteArray = key.copyOf()

        init {
            requireValidSipHashParameters(key, compressionRounds, finalizationRounds)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("key" to key)
    }

    /**
     * [SipHash](https://www.aumasson.jp/siphash/siphash.pdf), a keyed pseudorandom function with output size of 128
     * bits, using a 16 byte [key], [compressionRounds] compression rounds and [finalizationRounds] finalization rounds
     * (default: SipHash128-2-4)
     */
    @Deprecated("Use SipHash.sipHash128 from cryptohash-siphash")
    public class SipHash128(
        key: ByteArray,
        internal val compressionRounds: Int = 2,
        internal val finalizationRounds: Int = 4
    ) : Algorithm("SipHash128-$compressionRounds-$finalizationRounds", 8) {
        internal val key: ByteArray = key.copyOf()

        init {
            requireValidSipHashParameters(key, compressionRounds, finalizationRounds)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("key" to key)
    }

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 128 bits
     */
    @Deprecated(
        "Use Skein.skein256_128 from cryptohash-skein",
        ReplaceWith("Skein.skein256_128", "com.appmattus.crypto.Skein")
    )
    public data object Skein256_128 : Algorithm("Skein-256-128", 32), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 160 bits
     */
    @Deprecated(
        "Use Skein.skein256_160 from cryptohash-skein",
        ReplaceWith("Skein.skein256_160", "com.appmattus.crypto.Skein")
    )
    public data object Skein256_160 : Algorithm("Skein-256-160", 32), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 224 bits
     */
    @Deprecated(
        "Use Skein.skein256_224 from cryptohash-skein",
        ReplaceWith("Skein.skein256_224", "com.appmattus.crypto.Skein")
    )
    public data object Skein256_224 : Algorithm("Skein-256-224", 32), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 256 bits
     */
    @Deprecated(
        "Use Skein.skein256_256 from cryptohash-skein",
        ReplaceWith("Skein.skein256_256", "com.appmattus.crypto.Skein")
    )
    public data object Skein256_256 : Algorithm("Skein-256-256", 32), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 128 bits
     */
    @Deprecated(
        "Use Skein.skein512_128 from cryptohash-skein",
        ReplaceWith("Skein.skein512_128", "com.appmattus.crypto.Skein")
    )
    public data object Skein512_128 : Algorithm("Skein-512-128", 64), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 160 bits
     */
    @Deprecated(
        "Use Skein.skein512_160 from cryptohash-skein",
        ReplaceWith("Skein.skein512_160", "com.appmattus.crypto.Skein")
    )
    public data object Skein512_160 : Algorithm("Skein-512-160", 64), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 224 bits
     */
    @Deprecated(
        "Use Skein.skein512_224 from cryptohash-skein",
        ReplaceWith("Skein.skein512_224", "com.appmattus.crypto.Skein")
    )
    public data object Skein512_224 : Algorithm("Skein-512-224", 64), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 256 bits
     */
    @Deprecated(
        "Use Skein.skein512_256 from cryptohash-skein",
        ReplaceWith("Skein.skein512_256", "com.appmattus.crypto.Skein")
    )
    public data object Skein512_256 : Algorithm("Skein-512-256", 64), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 384 bits
     */
    @Deprecated(
        "Use Skein.skein512_384 from cryptohash-skein",
        ReplaceWith("Skein.skein512_384", "com.appmattus.crypto.Skein")
    )
    public data object Skein512_384 : Algorithm("Skein-512-384", 64), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 512 bits
     */
    @Deprecated(
        "Use Skein.skein512_512 from cryptohash-skein",
        ReplaceWith("Skein.skein512_512", "com.appmattus.crypto.Skein")
    )
    public data object Skein512_512 : Algorithm("Skein-512-512", 64), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 1024 bits and output size of 384 bits
     */
    @Deprecated(
        "Use Skein.skein1024_384 from cryptohash-skein",
        ReplaceWith("Skein.skein1024_384", "com.appmattus.crypto.Skein")
    )
    public data object Skein1024_384 : Algorithm("Skein-1024-384", 128), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 1024 bits and output size of 512 bits
     */
    @Deprecated(
        "Use Skein.skein1024_512 from cryptohash-skein",
        ReplaceWith("Skein.skein1024_512", "com.appmattus.crypto.Skein")
    )
    public data object Skein1024_512 : Algorithm("Skein-1024-512", 128), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 1024 bits and output size of 1024 bits
     */
    @Deprecated(
        "Use Skein.skein1024_1024 from cryptohash-skein",
        ReplaceWith("Skein.skein1024_1024", "com.appmattus.crypto.Skein")
    )
    public data object Skein1024_1024 : Algorithm("Skein-1024-1024", 128), Hmac

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of [blockSizeBits] bits and output size of [outputSizeBits] bits
     */
    @Deprecated("Use Skein.skeinKeyed or Skein.skein from cryptohash-skein")
    public open class Skein(internal val blockSizeBits: Int, internal val outputSizeBits: Int) :
        Algorithm("Skein-$blockSizeBits-$outputSizeBits", blockSizeBits shr 3) {
        init {
            require(blockSizeBits in SKEIN_BLOCK_SIZES) { "blockSizeBits must be one of $SKEIN_BLOCK_SIZES, was $blockSizeBits" }
            require(outputSizeBits in SKEIN_OUTPUT_SIZES) {
                "outputSizeBits must be one of $SKEIN_OUTPUT_SIZES, was $outputSizeBits"
            }
        }

        /**
         * [Skein] as [key]ed hash with internal state of [blockSizeBits] bits and output size of [outputSizeBits] bits
         */
        public class Keyed(
            blockSizeBits: Int,
            outputSizeBits: Int,
            key: ByteArray,
        ) : Skein(blockSizeBits, outputSizeBits) {
            internal val key: ByteArray = key.copyOf()

            init {
                require(key.isEmpty() || key.size >= SKEIN_MIN_KEY_SIZE) {
                    "key must be empty or at least $SKEIN_MIN_KEY_SIZE bytes, was ${key.size}"
                }
            }

            override val parameters: List<Pair<String, Any?>>
                get() = listOf("key" to key)
        }
    }

    /**
     * [SM3](https://en.wikipedia.org/wiki/SM3_(hash_function)) with output size of 256 bits
     */
    @Deprecated(
        "Use Sm3.sm3 from cryptohash-sm3",
        ReplaceWith("Sm3.sm3", "com.appmattus.crypto.Sm3")
    )
    public data object SM3 : Algorithm("SM3", 64), Hmac

    /**
     * [t1ha0-32le](https://github.com/erthink/t1ha) with output size of 64 bits
     */
    @Deprecated("Use T1ha.t1ha0_32le from cryptohash-t1ha")
    public class T1ha0_32le(internal val seed: ULong = 0u) : Algorithm("t1ha0-32le", 16) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [t1ha1-le](https://github.com/erthink/t1ha) with output size of 64 bits
     */
    @Deprecated("Use T1ha.t1ha1Le from cryptohash-t1ha")
    public class T1ha1_le(internal val seed: ULong = 0u) : Algorithm("t1ha1-le", 32) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [t1ha2-atonce](https://github.com/erthink/t1ha) with output size of 64 bits
     */
    @Deprecated("Use T1ha.t1ha2AtOnce from cryptohash-t1ha")
    public class T1ha2_AtOnce(internal val seed: ULong = 0u) : Algorithm("t1ha2-atonce", 32) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [t1ha2-atonce128](https://github.com/erthink/t1ha) with output size of 128 bits
     */
    @Deprecated("Use T1ha.t1ha2AtOnce128 from cryptohash-t1ha")
    public class T1ha2_AtOnce128(internal val seed: ULong = 0u) : Algorithm("t1ha2-atonce128", 32) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [t1ha2-stream](https://github.com/erthink/t1ha) with output size of 64 bits
     */
    @Deprecated("Use T1ha.t1ha2Stream from cryptohash-t1ha")
    public class T1ha2_Stream(internal val seedX: ULong = 0u, internal val seedY: ULong = seedX) : Algorithm("t1ha2-stream", 32) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seedX" to seedX, "seedY" to seedY)
    }

    /**
     * [t1ha2-stream128](https://github.com/erthink/t1ha) with output size of 128 bits
     */
    @Deprecated("Use T1ha.t1ha2Stream128 from cryptohash-t1ha")
    public class T1ha2_Stream128(internal val seedX: ULong = 0u, internal val seedY: ULong = seedX) : Algorithm("t1ha2-stream128", 32) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seedX" to seedX, "seedY" to seedY)
    }

    /**
     * [Tiger](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) with output size of 192 bits
     */
    @Deprecated(
        "Use Tiger.tiger from cryptohash-tiger",
        ReplaceWith("Tiger.tiger", "com.appmattus.crypto.Tiger")
    )
    public data object Tiger : Algorithm("Tiger", 64), Hmac

    /**
     * [Tiger2](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) with output size of 192 bits
     */
    @Deprecated(
        "Use Tiger.tiger2 from cryptohash-tiger",
        ReplaceWith("Tiger.tiger2", "com.appmattus.crypto.Tiger")
    )
    public data object Tiger2 : Algorithm("Tiger2", 64)

    /**
     * [TupleHash128](https://doi.org/10.6028/NIST.SP.800-185) from NIST SP 800-185, which hashes a tuple of byte
     * arrays, with output size of [outputSizeBits] bits (default: 256 bits) and an optional [customisation] string.
     *
     * Each call to [Digest.update] adds one element to the tuple, so `update(a); update(b)` hashes the tuple `(a, b)`,
     * which differs from `update(a + b)`. [hash] treats its input as a tuple with one element.
     */
    @Deprecated("Use Sp800185.tupleHash128 from cryptohash-keccak")
    public class TupleHash128(
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 256
    ) : Algorithm("TupleHash128", 168) {
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * [TupleHash256](https://doi.org/10.6028/NIST.SP.800-185) from NIST SP 800-185, which hashes a tuple of byte
     * arrays, with output size of [outputSizeBits] bits (default: 512 bits) and an optional [customisation] string.
     *
     * Each call to [Digest.update] adds one element to the tuple, so `update(a); update(b)` hashes the tuple `(a, b)`,
     * which differs from `update(a + b)`. [hash] treats its input as a tuple with one element.
     */
    @Deprecated("Use Sp800185.tupleHash256 from cryptohash-keccak")
    public class TupleHash256(
        customisation: ByteArray? = null,
        internal val outputSizeBits: Int = 512
    ) : Algorithm("TupleHash256", 136) {
        internal val customisation: ByteArray? = customisation?.copyOf()

        init {
            requireValidXofOutputSize(outputSizeBits)
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("customisation" to customisation, "outputSizeBits" to outputSizeBits)
    }

    /**
     * Latest version of [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(hash_function)) with output size of 512 bits
     */
    @Deprecated(
        "Use Whirlpool.whirlpool from cryptohash-whirlpool",
        ReplaceWith("Whirlpool.whirlpool", "com.appmattus.crypto.Whirlpool")
    )
    public data object Whirlpool : Algorithm("Whirlpool", 64), Hmac

    /**
     * Original version of [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(hash_function)) with output size of 512 bits
     */
    @Deprecated(
        "Use Whirlpool.whirlpool0 from cryptohash-whirlpool",
        ReplaceWith("Whirlpool.whirlpool0", "com.appmattus.crypto.Whirlpool")
    )
    public data object Whirlpool0 : Algorithm("Whirlpool-0", 64)

    /**
     * First version of [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(hash_function)) with output size of 512 bits
     */
    @Deprecated(
        "Use Whirlpool.whirlpoolT from cryptohash-whirlpool",
        ReplaceWith("Whirlpool.whirlpoolT", "com.appmattus.crypto.Whirlpool")
    )
    public data object WhirlpoolT : Algorithm("Whirlpool-T", 64)

    /**
     * [wyhash](https://github.com/wangyi-fudan/wyhash) with output size of 64 bits
     */
    @Deprecated("Use Wyhash.wyhash64 from cryptohash-wyhash")
    public class Wyhash(
        internal val seed: ULong = 0u,
        secret: List<ULong> = com.appmattus.crypto.Wyhash.defaultSecret,
        internal val extraProtection: Boolean = false
    ) : Algorithm("wyhash-64", 48) {
        internal val secret: List<ULong> = secret.toList()

        init {
            require(secret.size >= WYHASH_SECRET_SIZE) {
                "secret must contain at least $WYHASH_SECRET_SIZE values, was ${secret.size}"
            }
        }

        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed, "secret" to secret, "extraProtection" to extraProtection)

        public companion object {
            public fun makeSecret(seed: ULong): List<ULong> = com.appmattus.crypto.Wyhash.makeSecret(seed)
        }
    }

    /**
     * [wyhash](https://github.com/wangyi-fudan/wyhash) with output size of 32 bits
     */
    @Deprecated("Use Wyhash.wyhash32 from cryptohash-wyhash")
    public class Wyhash32(internal val seed: UInt = 0u) : Algorithm("wyhash-32", 8) {
        override val parameters: List<Pair<String, Any?>>
            get() = listOf("seed" to seed)
    }

    /**
     * [xxHash](https://github.com/Cyan4973/xxHash) with output size of 32 bits
     */
    public data class XXHash32(val seed: Int = 0) : Algorithm("XXH32", 16)

    /**
     * [xxHash](https://github.com/Cyan4973/xxHash) with output size of 64 bits
     */
    public data class XXHash64(val seed: Long = 0) : Algorithm("XXH64", 32)

    /**
     * [xxHash3](https://github.com/Cyan4973/xxHash) with output size of 64 bits
     */
    @Deprecated("Use XxHash.xxh3_64 from cryptohash-xxhash")
    public open class XXH3_64 : Algorithm("XXH3-64", 128) {
        /**
         * [XXH3_64] using [seed] with output size of 64 bits
         */
        public class Seeded(internal val seed: Long) : XXH3_64() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seed" to seed)
        }

        /**
         * [XXH3_64] using [secret] with output size of 64 bits
         */
        public class Secret(secret: ByteArray) : XXH3_64() {
            @Suppress("MemberNameEqualsClassName")
            internal val secret: ByteArray = secret.copyOf()

            init {
                require(secret.size >= XXH3_SECRET_SIZE_MIN) {
                    "secret must be at least $XXH3_SECRET_SIZE_MIN bytes, was ${secret.size}"
                }
            }

            override val parameters: List<Pair<String, Any?>>
                get() = listOf("secret" to secret)
        }
    }

    /**
     * [xxHash3](https://github.com/Cyan4973/xxHash) with output size of 128 bits
     */
    @Deprecated("Use XxHash.xxh3_128 from cryptohash-xxhash")
    public open class XXH3_128 : Algorithm("XXH3-128", 128) {
        /**
         * [XXH3_128] using [seed] with output size of 128 bits
         */
        public class Seeded(internal val seed: Long) : XXH3_128() {
            override val parameters: List<Pair<String, Any?>>
                get() = listOf("seed" to seed)
        }

        /**
         * [XXH3_128] using [secret] with output size of 128 bits
         */
        public class Secret(secret: ByteArray) : XXH3_128() {
            @Suppress("MemberNameEqualsClassName")
            internal val secret: ByteArray = secret.copyOf()

            init {
                require(secret.size >= XXH3_SECRET_SIZE_MIN) {
                    "secret must be at least $XXH3_SECRET_SIZE_MIN bytes, was ${secret.size}"
                }
            }

            override val parameters: List<Pair<String, Any?>>
                get() = listOf("secret" to secret)
        }
    }

    /**
     * Create a [Digest] of the [Algorithm] for creating hashes.
     *
     * Where the platform has its own faster implementation of the algorithm, such as JVM `MessageDigest` or Apple
     * CommonCrypto, the digest uses it. The results are identical either way.
     */
    public fun createDigest(): Digest = CoreDigest.create(this)

    /**
     * Create a hash of [input] using the [Algorithm]
     */
    public fun hash(input: ByteArray): ByteArray = createDigest().digest(input)

    /**
     * Create a hash of the [length] bytes of [input] starting at [offset] using the [Algorithm]
     *
     * @throws IndexOutOfBoundsException if [offset] and [length] don't fit within [input]
     */
    public fun hash(input: ByteArray, offset: Int, length: Int): ByteArray {
        checkRange(input, offset, length)
        return createDigest().run {
            update(input, offset, length)
            digest()
        }
    }

    /**
     * Create a hash of the UTF-8 encoding of [input] using the [Algorithm]
     */
    public fun hash(input: String): ByteArray = hash(input.encodeToByteArray())
}

private fun parameterEquals(a: Any?, b: Any?): Boolean = when (a) {
    is ByteArray -> b is ByteArray && a.contentEquals(b)
    is LongArray -> b is LongArray && a.contentEquals(b)
    else -> a == b
}

private fun parameterHashCode(value: Any?): Int = when (value) {
    is ByteArray -> value.contentHashCode()
    is LongArray -> value.contentHashCode()
    else -> value.hashCode()
}

private fun parameterToString(value: Any?): String = when (value) {
    is ByteArray -> "ByteArray(size=${value.size})"
    is LongArray -> "LongArray(size=${value.size})"
    is List<*> -> "List(size=${value.size})"
    else -> value.toString()
}

private const val ASCON_CUSTOMISATION_MAX_SIZE = 256

private fun requireValidAsconOutputSize(outputSizeBits: Int) {
    require(outputSizeBits > 0 && outputSizeBits % 8 == 0) {
        "outputSizeBits must be a positive multiple of 8, was $outputSizeBits"
    }
}

private val SKEIN_BLOCK_SIZES = listOf(256, 512, 1024)
private val SKEIN_OUTPUT_SIZES = listOf(128, 160, 224, 256, 384, 512, 1024)
private const val SKEIN_MIN_KEY_SIZE = 16
private const val HIGHWAY_HASH_KEY_SIZE = 4
private const val WYHASH_SECRET_SIZE = 4

private const val SIPHASH_KEY_SIZE = 16

private const val BLAKE3_DEFAULT_DIGEST_LENGTH = 32

private const val BLAKE3_KEY_SIZE = 32

private fun requireValidXofOutputSize(outputSizeBits: Int) {
    require(outputSizeBits > 0 && outputSizeBits % 8 == 0) {
        "outputSizeBits must be a positive multiple of 8, was $outputSizeBits"
    }
}

private fun requireValidSipHashParameters(key: ByteArray, compressionRounds: Int, finalizationRounds: Int) {
    require(key.size == SIPHASH_KEY_SIZE) { "key must be exactly $SIPHASH_KEY_SIZE bytes, was ${key.size}" }
    require(compressionRounds > 0) { "compressionRounds must be greater than 0, was $compressionRounds" }
    require(finalizationRounds > 0) { "finalizationRounds must be greater than 0, was $finalizationRounds" }
}
