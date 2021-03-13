/*
 * Copyright 2021 Appmattus Limited
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

import com.appmattus.crypto.internal.core.blake3.Hasher

@Suppress("MagicNumber", "ClassName")
sealed class Algorithm(val algorithmName: String, internal val blockLength: Int) {
    object Adler32 : Algorithm("Adler32", 32)

    object BLAKE224 : Algorithm("BLAKE-224", 64)
    object BLAKE256 : Algorithm("BLAKE-256", 64)
    object BLAKE384 : Algorithm("BLAKE-384", 128)
    object BLAKE512 : Algorithm("BLAKE-512", 128)

    object Blake2s_128 : Algorithm("BLAKE2S-128", 64)
    object Blake2s_160 : Algorithm("BLAKE2S-160", 64)
    object Blake2s_224 : Algorithm("BLAKE2S-224", 64)
    object Blake2s_256 : Algorithm("BLAKE2S-256", 64)

    open class Blake2s(val outputSizeBits: Int = 256) : Algorithm("Blake2s-$outputSizeBits-internal", 64) {
        class Keyed(
            val key: ByteArray,
            val salt: ByteArray? = null,
            val personalisation: ByteArray? = null,
            outputSizeBits: Int = 256
        ) : Blake2s(outputSizeBits)
    }

    object Blake2b_160 : Algorithm("BLAKE2B-160", 128)
    object Blake2b_256 : Algorithm("BLAKE2B-256", 128)
    object Blake2b_384 : Algorithm("BLAKE2B-384", 128)
    object Blake2b_512 : Algorithm("BLAKE2B-512", 128)

    open class Blake2b(val outputSizeBits: Int = 512) : Algorithm("Blake2b-$outputSizeBits-internal", 128) {
        class Keyed(
            val key: ByteArray,
            val salt: ByteArray? = null,
            val personalisation: ByteArray? = null,
            outputSizeBits: Int = 512
        ) : Blake2b(outputSizeBits)
    }

    open class Blake3(val digestLength: Int = Hasher.DEFAULT_HASH_LEN) : Algorithm("Blake3-${digestLength shl 3}-internal", 64) {
        class Keyed(val key: ByteArray, digestLength: Int = Hasher.DEFAULT_HASH_LEN) : Blake3(digestLength)
        class DeriveKey(val context: ByteArray, digestLength: Int = Hasher.DEFAULT_HASH_LEN) : Blake3(digestLength)
    }

    object BMW224 : Algorithm("BMW-224", 64)
    object BMW256 : Algorithm("BMW-256", 64)
    object BMW384 : Algorithm("BMW-384", 128)
    object BMW512 : Algorithm("BMW-512", 128)

    object CRC32 : Algorithm("CRC32", 32)

    class cSHAKE128(
        val customisation: ByteArray? = null,
        val functionName: ByteArray? = null
    ) : Algorithm("CRC32", 64)

    class cSHAKE256(
        val customisation: ByteArray? = null,
        val functionName: ByteArray? = null
    ) : Algorithm("CRC32", 128)

    object CubeHash224 : Algorithm("CubeHash-224", 32)
    object CubeHash256 : Algorithm("CubeHash-256", 32)
    object CubeHash384 : Algorithm("CubeHash-384", 32)
    object CubeHash512 : Algorithm("CubeHash-512", 32)

    object DSTU7564_256 : Algorithm("DSTU7564-256", 64)
    object DSTU7564_384 : Algorithm("DSTU7564-384", 128)
    object DSTU7564_512 : Algorithm("DSTU7564-512", 128)

    object ECHO224 : Algorithm("ECHO-224", 192)
    object ECHO256 : Algorithm("ECHO-256", 192)
    object ECHO384 : Algorithm("ECHO-384", 128)
    object ECHO512 : Algorithm("ECHO-512", 128)

    object Fugue224 : Algorithm("Fugue-224", 28)
    object Fugue256 : Algorithm("Fugue-256", 32)
    object Fugue384 : Algorithm("Fugue-384", 48)
    object Fugue512 : Algorithm("Fugue-512", 64)

    object GOST3411_94 : Algorithm("GOST3411", 32)
    object GOST3411_2012_256 : Algorithm("GOST3411-2012-256", 64)
    object GOST3411_2012_512 : Algorithm("GOST3411-2012-512", 64)

    object Groestl224 : Algorithm("Groestl-224", 64)
    object Groestl256 : Algorithm("Groestl-256", 64)
    object Groestl384 : Algorithm("Groestl-384", 128)
    object Groestl512 : Algorithm("Groestl-512", 128)

    object Hamsi224 : Algorithm("Hamsi-224", 32)
    object Hamsi256 : Algorithm("Hamsi-256", 32)
    object Hamsi384 : Algorithm("Hamsi-384", 32)
    object Hamsi512 : Algorithm("Hamsi-512", 32)

    object Haraka256_256 : Algorithm("Haraka-256", 32)
    object Haraka512_256 : Algorithm("Haraka-512", 64)

    object HAVAL_3_128 : Algorithm("HAVAL-3-128", 128)
    object HAVAL_3_160 : Algorithm("HAVAL-3-160", 128)
    object HAVAL_3_192 : Algorithm("HAVAL-3-192", 128)
    object HAVAL_3_224 : Algorithm("HAVAL-3-224", 128)
    object HAVAL_3_256 : Algorithm("HAVAL-3-256", 128)
    object HAVAL_4_128 : Algorithm("HAVAL-4-128", 128)
    object HAVAL_4_160 : Algorithm("HAVAL-4-160", 128)
    object HAVAL_4_192 : Algorithm("HAVAL-4-192", 128)
    object HAVAL_4_224 : Algorithm("HAVAL-4-224", 128)
    object HAVAL_4_256 : Algorithm("HAVAL-4-256", 128)
    object HAVAL_5_128 : Algorithm("HAVAL-5-128", 128)
    object HAVAL_5_160 : Algorithm("HAVAL-5-160", 128)
    object HAVAL_5_192 : Algorithm("HAVAL-5-192", 128)
    object HAVAL_5_224 : Algorithm("HAVAL-5-224", 128)
    object HAVAL_5_256 : Algorithm("HAVAL-5-256", 128)

    object JH224 : Algorithm("JH-224", 64)
    object JH256 : Algorithm("JH-256", 64)
    object JH384 : Algorithm("JH-384", 64)
    object JH512 : Algorithm("JH-512", 64)

    object Keccak224 : Algorithm("Keccak-224", 64)
    object Keccak256 : Algorithm("Keccak-256", 64)
    object Keccak288 : Algorithm("Keccak-288", 64)
    object Keccak384 : Algorithm("Keccak-384", 128)
    object Keccak512 : Algorithm("Keccak-512", 128)

    object Luffa224 : Algorithm("Luffa-224", 32)
    object Luffa256 : Algorithm("Luffa-256", 32)
    object Luffa384 : Algorithm("Luffa-384", 32)
    object Luffa512 : Algorithm("Luffa-512", 32)

    object MD2 : Algorithm("MD2", 16)
    object MD4 : Algorithm("MD4", 64)
    object MD5 : Algorithm("MD5", 64)

    object PANAMA : Algorithm("PANAMA", 32)

    object RadioGatun32 : Algorithm("RadioGatún[32]", 156)
    object RadioGatun64 : Algorithm("RadioGatún[64]", 312)

    object RipeMD : Algorithm("RipeMD", 64)
    object RipeMD128 : Algorithm("RipeMD128", 64)
    object RipeMD160 : Algorithm("RipeMD160", 64)
    object RipeMD256 : Algorithm("RipeMD256", 64)
    object RipeMD320 : Algorithm("RipeMD320", 64)

    object SHA_0 : Algorithm("SHA-0", 64)
    object SHA_1 : Algorithm("SHA-1", 64)
    object SHA_224 : Algorithm("SHA-224", 64)
    object SHA_256 : Algorithm("SHA-256", 64)
    object SHA_384 : Algorithm("SHA-384", 128)
    object SHA_512 : Algorithm("SHA-512", 128)
    object SHA_512_224 : Algorithm("SHA-512/224", 128)
    object SHA_512_256 : Algorithm("SHA-512/256", 128)

    object SHA3_224 : Algorithm("SHA3-224", 64)
    object SHA3_256 : Algorithm("SHA3-256", 64)
    object SHA3_384 : Algorithm("SHA3-384", 128)
    object SHA3_512 : Algorithm("SHA3-512", 128)

    object Shabal192 : Algorithm("Shabal-192", 64)
    object Shabal224 : Algorithm("Shabal-224", 64)
    object Shabal256 : Algorithm("Shabal-256", 64)
    object Shabal384 : Algorithm("Shabal-384", 64)
    object Shabal512 : Algorithm("Shabal-512", 64)

    object SHAKE128 : Algorithm("SHAKE128", 64)
    object SHAKE256 : Algorithm("SHAKE256", 128)

    object SHAvite224 : Algorithm("SHAvite-224", 64)
    object SHAvite256 : Algorithm("SHAvite-256", 64)
    object SHAvite384 : Algorithm("SHAvite-384", 128)
    object SHAvite512 : Algorithm("SHAvite-512", 128)

    object SIMD224 : Algorithm("SIMD-224", 64)
    object SIMD256 : Algorithm("SIMD-256", 64)
    object SIMD384 : Algorithm("SIMD-384", 128)
    object SIMD512 : Algorithm("SIMD-512", 128)

    object Skein256_128 : Algorithm("Skein-256-128", 32)
    object Skein256_160 : Algorithm("Skein-256-160", 32)
    object Skein256_224 : Algorithm("Skein-256-224", 32)
    object Skein256_256 : Algorithm("Skein-256-256", 32)
    object Skein512_128 : Algorithm("Skein-512-128", 64)
    object Skein512_160 : Algorithm("Skein-512-160", 64)
    object Skein512_224 : Algorithm("Skein-512-224", 64)
    object Skein512_256 : Algorithm("Skein-512-256", 64)
    object Skein512_384 : Algorithm("Skein-512-384", 64)
    object Skein512_512 : Algorithm("Skein-512-512", 64)
    object Skein1024_384 : Algorithm("Skein-1024-384", 128)
    object Skein1024_512 : Algorithm("Skein-1024-512", 128)
    object Skein1024_1024 : Algorithm("Skein-1024-1024", 128)

    open class Skein(val blockSizeBits: Int, val outputSizeBits: Int) :
        Algorithm("Skein-$blockSizeBits-$outputSizeBits-internal", blockSizeBits shr 3) {
        class Keyed(
            blockSizeBits: Int,
            outputSizeBits: Int,
            val key: ByteArray,
        ) : Skein(blockSizeBits, outputSizeBits)
    }

    object SM3 : Algorithm("SM3", 64)

    object Tiger : Algorithm("Tiger", 64)
    object Tiger2 : Algorithm("Tiger2", 64)

    object Whirlpool : Algorithm("Whirlpool", 64)
    object Whirlpool0 : Algorithm("Whirlpool-0", 64)
    object WhirlpoolT : Algorithm("Whirlpool-T", 64)
}
