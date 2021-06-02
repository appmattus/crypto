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

import com.appmattus.crypto.internal.CoreDigest
import com.appmattus.crypto.internal.core.blake3.Hasher

@Suppress("MagicNumber", "ClassName")
public sealed class Algorithm(public val algorithmName: String, internal val blockLength: Int) {
    /**
     * [Adler-32](https://en.wikipedia.org/wiki/Adler-32) with output size of 32 bits
     */
    public object Adler32 : Algorithm("Adler32", 32)

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 224 bits
     */
    public object BLAKE224 : Algorithm("BLAKE-224", 64)

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 256 bits
     */
    public object BLAKE256 : Algorithm("BLAKE-256", 64)

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 384 bits
     */
    public object BLAKE384 : Algorithm("BLAKE-384", 128)

    /**
     * [BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)) with output size of 512 bits
     */
    public object BLAKE512 : Algorithm("BLAKE-512", 128)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 128 bits
     */
    public object Blake2s_128 : Algorithm("BLAKE2S-128", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 160 bits
     */
    public object Blake2s_160 : Algorithm("BLAKE2S-160", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 224 bits
     */
    public object Blake2s_224 : Algorithm("BLAKE2S-224", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of 256 bits
     */
    public object Blake2s_256 : Algorithm("BLAKE2S-256", 64)

    /**
     * [BLAKE2s](https://www.blake2.net) with output size of [outputSizeBits] bits (default: 256 bits)
     */
    public open class Blake2s(internal val outputSizeBits: Int = 256) : Algorithm("Blake2s-$outputSizeBits", 64) {
        /**
         * [Blake2s] tuned to your specific requirements, such as [key]ed hashing, hashing with a [salt], or
         * [personalisation], or any combination thereof with output size of [outputSizeBits] bits (default: 256 bits)
         */
        public class Keyed(
            internal val key: ByteArray,
            internal val salt: ByteArray? = null,
            internal val personalisation: ByteArray? = null,
            outputSizeBits: Int = 256
        ) : Blake2s(outputSizeBits)
    }

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 160 bits
     */
    public object Blake2b_160 : Algorithm("BLAKE2B-160", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 256 bits
     */
    public object Blake2b_256 : Algorithm("BLAKE2B-256", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 384 bits
     */
    public object Blake2b_384 : Algorithm("BLAKE2B-384", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of 512 bits
     */
    public object Blake2b_512 : Algorithm("BLAKE2B-512", 128)

    /**
     * [BLAKE2b](https://www.blake2.net) with output size of [outputSizeBits] bits (default: 512 bits)
     */
    public open class Blake2b(internal val outputSizeBits: Int = 512) : Algorithm("Blake2b-$outputSizeBits", 128) {
        /**
         * [Blake2b] tuned to your specific requirements, such as [key]ed hashing, hashing with a [salt], or
         * [personalisation], or any combination thereof with output size of [outputSizeBits] bits (default: 512 bits)
         */
        public class Keyed(
            internal val key: ByteArray,
            internal val salt: ByteArray? = null,
            internal val personalisation: ByteArray? = null,
            outputSizeBits: Int = 512
        ) : Blake2b(outputSizeBits)
    }

    /**
     * [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) with output size of [digestLength] bytes (default: 32 bytes)
     */
    public open class Blake3(internal val digestLength: Int = Hasher.DEFAULT_HASH_LEN) : Algorithm("Blake3-${digestLength shl 3}", 64) {
        /**
         * [Blake3] using [key]ed hashing with output size of [digestLength] bytes (default: 32 bytes)
         */
        public class Keyed(internal val key: ByteArray, digestLength: Int = Hasher.DEFAULT_HASH_LEN) : Blake3(digestLength)

        /**
         * [Blake3] using [context] to derive a key with output size of [digestLength] bytes (default: 32 bytes)
         */
        public class DeriveKey(internal val context: ByteArray, digestLength: Int = Hasher.DEFAULT_HASH_LEN) : Blake3(digestLength)
    }

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 224 bits
     */
    public object BMW224 : Algorithm("BMW-224", 64)

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 256 bits
     */
    public object BMW256 : Algorithm("BMW-256", 64)

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 384 bits
     */
    public object BMW384 : Algorithm("BMW-384", 128)

    /**
     * [Blue Midnight Wish](http://people.item.ntnu.no/~danilog/Hash/BMW-SecondRound/Supporting_Documentation/BlueMidnightWishDocumentation.pdf)
     * with output size of 512 bits
     */
    public object BMW512 : Algorithm("BMW-512", 128)

    /**
     * [CRC](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) with output size of 32 bits
     */
    public object CRC32 : Algorithm("CRC32", 32)

    /**
     * [cSHAKE](https://keccak.team/keccak.html) with output size of 128 bits
     */
    public class cSHAKE128(
        internal val customisation: ByteArray? = null,
        internal val functionName: ByteArray? = null
    ) : Algorithm("cSHAKE128", 64)

    /**
     * [cSHAKE](https://keccak.team/keccak.html) with output size of 256 bits
     */
    public class cSHAKE256(
        internal val customisation: ByteArray? = null,
        internal val functionName: ByteArray? = null
    ) : Algorithm("cSHAKE256", 128)

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 224 bits
     */
    public object CubeHash224 : Algorithm("CubeHash-224", 32)

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 256 bits
     */
    public object CubeHash256 : Algorithm("CubeHash-256", 32)

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 384 bits
     */
    public object CubeHash384 : Algorithm("CubeHash-384", 32)

    /**
     * [CubeHash](https://cubehash.cr.yp.to/) with output size of 512 bits
     */
    public object CubeHash512 : Algorithm("CubeHash-512", 32)

    /**
     * [ECHO](https://crypto.orange-labs.fr/ECHO/) with output size 224 bits
     */
    public object ECHO224 : Algorithm("ECHO-224", 192)

    /**
     * [ECHO](https://crypto.orange-labs.fr/ECHO/) with output size 256 bits
     */
    public object ECHO256 : Algorithm("ECHO-256", 192)

    /**
     * [ECHO](https://crypto.orange-labs.fr/ECHO/) with output size 384 bits
     */
    public object ECHO384 : Algorithm("ECHO-384", 128)

    /**
     * [ECHO](https://crypto.orange-labs.fr/ECHO/) with output size 512 bits
     */
    public object ECHO512 : Algorithm("ECHO-512", 128)

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 224 bits
     */
    public object Fugue224 : Algorithm("Fugue-224", 28)

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 256 bits
     */
    public object Fugue256 : Algorithm("Fugue-256", 32)

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 384 bits
     */
    public object Fugue384 : Algorithm("Fugue-384", 48)

    /**
     * [Fugue](https://researcher.watson.ibm.com/researcher/files/us-csjutla/fugue_Oct09.pdf) with output size 512 bits
     */
    public object Fugue512 : Algorithm("Fugue-512", 64)

    /**
     * [GOST R 34.11-94](https://en.wikipedia.org/wiki/GOST_(hash_function)) with output size 256 bits
     */
    public object GOST3411_94 : Algorithm("GOST3411", 32)

    /**
     * [GOST R 34.11-2012](https://en.wikipedia.org/wiki/GOST_(hash_function)) with output size 256 bits
     */
    public object GOST3411_2012_256 : Algorithm("GOST3411-2012-256", 64)

    /**
     * [GOST R 34.11-2012](https://en.wikipedia.org/wiki/GOST_(hash_function)) with output size 512 bits
     */
    public object GOST3411_2012_512 : Algorithm("GOST3411-2012-512", 64)

    /**
     * [Grøstl](https://www.groestl.info) with output size 224 bits
     */
    public object Groestl224 : Algorithm("Groestl-224", 64)

    /**
     * [Grøstl](https://www.groestl.info) with output size 256 bits
     */
    public object Groestl256 : Algorithm("Groestl-256", 64)

    /**
     * [Grøstl](https://www.groestl.info) with output size 384 bits
     */
    public object Groestl384 : Algorithm("Groestl-384", 128)

    /**
     * [Grøstl](https://www.groestl.info) with output size 512 bits
     */
    public object Groestl512 : Algorithm("Groestl-512", 128)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 224 bits
     */
    public object Hamsi224 : Algorithm("Hamsi-224", 32)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 256 bits
     */
    public object Hamsi256 : Algorithm("Hamsi-256", 32)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 384 bits
     */
    public object Hamsi384 : Algorithm("Hamsi-384", 32)

    /**
     * [Hamsi](https://www.esat.kuleuven.be/cosic/publications/article-1203.pdf) with output size 512 bits
     */
    public object Hamsi512 : Algorithm("Hamsi-512", 32)

    /**
     * [Haraka v2](https://github.com/kste/haraka) with output size 256 bits
     */
    public object Haraka256_256 : Algorithm("Haraka-256", 32)

    /**
     * [Haraka v2](https://github.com/kste/haraka) with output size 256 bits
     */
    public object Haraka512_256 : Algorithm("Haraka-512", 64)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 128 bits
     */
    public object HAVAL_3_128 : Algorithm("HAVAL-3-128", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 160 bits
     */
    public object HAVAL_3_160 : Algorithm("HAVAL-3-160", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 192 bits
     */
    public object HAVAL_3_192 : Algorithm("HAVAL-3-192", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 224 bits
     */
    public object HAVAL_3_224 : Algorithm("HAVAL-3-224", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 3 rounds and output size 256 bits
     */
    public object HAVAL_3_256 : Algorithm("HAVAL-3-256", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 128 bits
     */
    public object HAVAL_4_128 : Algorithm("HAVAL-4-128", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 160 bits
     */
    public object HAVAL_4_160 : Algorithm("HAVAL-4-160", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 192 bits
     */
    public object HAVAL_4_192 : Algorithm("HAVAL-4-192", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 224 bits
     */
    public object HAVAL_4_224 : Algorithm("HAVAL-4-224", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 4 rounds and output size 256 bits
     */
    public object HAVAL_4_256 : Algorithm("HAVAL-4-256", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 128 bits
     */
    public object HAVAL_5_128 : Algorithm("HAVAL-5-128", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 160 bits
     */
    public object HAVAL_5_160 : Algorithm("HAVAL-5-160", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 192 bits
     */
    public object HAVAL_5_192 : Algorithm("HAVAL-5-192", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 224 bits
     */
    public object HAVAL_5_224 : Algorithm("HAVAL-5-224", 128)

    /**
     * [HAVAL](https://en.wikipedia.org/wiki/HAVAL) with 5 rounds and output size 256 bits
     */
    public object HAVAL_5_256 : Algorithm("HAVAL-5-256", 128)

    /**
     * [JH](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 224 bits
     */
    public object JH224 : Algorithm("JH-224", 64)

    /**
     * [JH](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 256 bits
     */
    public object JH256 : Algorithm("JH-256", 64)

    /**
     * [JH](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 384 bits
     */
    public object JH384 : Algorithm("JH-384", 64)

    /**
     * [JH](https://en.wikipedia.org/wiki/JH_(hash_function)) with output size 512 bits
     */
    public object JH512 : Algorithm("JH-512", 64)

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 224 bits
     */
    public object Keccak224 : Algorithm("Keccak-224", 64)

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 256 bits
     */
    public object Keccak256 : Algorithm("Keccak-256", 64)

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 288 bits
     */
    public object Keccak288 : Algorithm("Keccak-288", 64)

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 384 bits
     */
    public object Keccak384 : Algorithm("Keccak-384", 128)

    /**
     * [Keccak](https://keccak.team/keccak.html) without output size 512 bits
     */
    public object Keccak512 : Algorithm("Keccak-512", 128)

    /**
     * [Kupyna (aka DSTU7564)](https://en.wikipedia.org/wiki/Kupyna) with output size 256 bits
     */
    public object Kupyna_256 : Algorithm("Kupyna-256", 64)

    /**
     * [Kupyna (aka DSTU7564)](https://en.wikipedia.org/wiki/Kupyna) with output size 384 bits
     */
    public object Kupyna_384 : Algorithm("Kupyna-384", 128)

    /**
     * [Kupyna (aka DSTU7564)](https://en.wikipedia.org/wiki/Kupyna) with output size 512 bits
     */
    public object Kupyna_512 : Algorithm("Kupyna-512", 128)

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 224 bits
     */
    public object Luffa224 : Algorithm("Luffa-224", 32)

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 256 bits
     */
    public object Luffa256 : Algorithm("Luffa-256", 32)

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 384 bits
     */
    public object Luffa384 : Algorithm("Luffa-384", 32)

    /**
     * [Luffa](https://www.hitachi.com/rd/yrl/crypto/luffa/) with output size of 512 bits
     */
    public object Luffa512 : Algorithm("Luffa-512", 32)

    /**
     * [MD2](https://en.wikipedia.org/wiki/MD2_(hash_function)) with output size of 128 bits
     */
    public object MD2 : Algorithm("MD2", 16)

    /**
     * [MD4](https://en.wikipedia.org/wiki/MD4) with output size of 128 bits
     */
    public object MD4 : Algorithm("MD4", 64)

    /**
     * [MD5](https://en.wikipedia.org/wiki/MD5) with output size of 128 bits
     */
    public object MD5 : Algorithm("MD5", 64)

    /**
     * [Panama](https://en.wikipedia.org/wiki/Panama_(cryptography)) with output size of 256 bits
     */
    public object PANAMA : Algorithm("PANAMA", 32)

    /**
     * [RadioGatún](https://en.wikipedia.org/wiki/RadioGatún) with 32-bit word width and output size of 256 bits
     */
    public object RadioGatun32 : Algorithm("RadioGatún[32]", 156)

    /**
     * [RadioGatún](https://en.wikipedia.org/wiki/RadioGatún) with 64-bit word width and output size of 256 bits
     */
    public object RadioGatun64 : Algorithm("RadioGatún[64]", 312)

    /**
     * Original [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 128 bits
     */
    public object RipeMD : Algorithm("RipeMD", 64)

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 128 bits
     */
    public object RipeMD128 : Algorithm("RipeMD128", 64)

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 160 bits
     */
    public object RipeMD160 : Algorithm("RipeMD160", 64)

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 256 bits
     */
    public object RipeMD256 : Algorithm("RipeMD256", 64)

    /**
     * Strengthened [RipeMD](https://en.wikipedia.org/wiki/RIPEMD) with output size of 320 bits
     */
    public object RipeMD320 : Algorithm("RipeMD320", 64)

    /**
     * [SHA-0](https://en.wikipedia.org/wiki/SHA-1#Development) with output size of 160 bits
     */
    public object SHA_0 : Algorithm("SHA-0", 64)

    /**
     * [SHA-1](https://en.wikipedia.org/wiki/SHA-1) with output size of 160 bits
     */
    public object SHA_1 : Algorithm("SHA-1", 64)

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 224 bits
     */
    public object SHA_224 : Algorithm("SHA-224", 64)

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 256 bits
     */
    public object SHA_256 : Algorithm("SHA-256", 64)

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 384 bits
     */
    public object SHA_384 : Algorithm("SHA-384", 128)

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 512 bits
     */
    public object SHA_512 : Algorithm("SHA-512", 128)

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 224 bits
     */
    public object SHA_512_224 : Algorithm("SHA-512/224", 128)

    /**
     * [SHA-2](https://en.wikipedia.org/wiki/SHA-2) with output size of 256 bits
     */
    public object SHA_512_256 : Algorithm("SHA-512/256", 128)

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 224 bits
     */
    public object SHA3_224 : Algorithm("SHA3-224", 64)

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 256 bits
     */
    public object SHA3_256 : Algorithm("SHA3-256", 64)

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 384 bits
     */
    public object SHA3_384 : Algorithm("SHA3-384", 128)

    /**
     * [SHA-3](https://keccak.team/keccak.html) with output size of 512 bits
     */
    public object SHA3_512 : Algorithm("SHA3-512", 128)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 192 bits
     */
    public object Shabal192 : Algorithm("Shabal-192", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 224 bits
     */
    public object Shabal224 : Algorithm("Shabal-224", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 256 bits
     */
    public object Shabal256 : Algorithm("Shabal-256", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 384 bits
     */
    public object Shabal384 : Algorithm("Shabal-384", 64)

    /**
     * [Shabal](https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf) with output size of 512 bits
     */
    public object Shabal512 : Algorithm("Shabal-512", 64)

    /**
     * [SHAKE](https://keccak.team/keccak.html) with output size of 128 bits
     */
    public object SHAKE128 : Algorithm("SHAKE128", 64)

    /**
     * [SHAKE](https://keccak.team/keccak.html) with output size of 256 bits
     */
    public object SHAKE256 : Algorithm("SHAKE256", 128)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 224 bits
     */
    public object SHAvite224 : Algorithm("SHAvite-224", 64)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 256 bits
     */
    public object SHAvite256 : Algorithm("SHAvite-256", 64)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 384 bits
     */
    public object SHAvite384 : Algorithm("SHAvite-384", 128)

    /**
     * [SHAvite-3](https://www.cs.technion.ac.il/~orrd/SHAvite-3/) with output size of 512 bits
     */
    public object SHAvite512 : Algorithm("SHAvite-512", 128)

    /**
     * [SIMD](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 224 bits
     */
    public object SIMD224 : Algorithm("SIMD-224", 64)

    /**
     * [SIMD](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 256 bits
     */
    public object SIMD256 : Algorithm("SIMD-256", 64)

    /**
     * [SIMD](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 384 bits
     */
    public object SIMD384 : Algorithm("SIMD-384", 128)

    /**
     * [SIMD](https://en.wikipedia.org/wiki/SIMD_(hash_function)) with output size of 512 bits
     */
    public object SIMD512 : Algorithm("SIMD-512", 128)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 128 bits
     */
    public object Skein256_128 : Algorithm("Skein-256-128", 32)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 160 bits
     */
    public object Skein256_160 : Algorithm("Skein-256-160", 32)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 224 bits
     */
    public object Skein256_224 : Algorithm("Skein-256-224", 32)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 256 bits and output size of 256 bits
     */
    public object Skein256_256 : Algorithm("Skein-256-256", 32)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 128 bits
     */
    public object Skein512_128 : Algorithm("Skein-512-128", 64)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 160 bits
     */
    public object Skein512_160 : Algorithm("Skein-512-160", 64)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 224 bits
     */
    public object Skein512_224 : Algorithm("Skein-512-224", 64)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 256 bits
     */
    public object Skein512_256 : Algorithm("Skein-512-256", 64)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 384 bits
     */
    public object Skein512_384 : Algorithm("Skein-512-384", 64)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 512 bits and output size of 512 bits
     */
    public object Skein512_512 : Algorithm("Skein-512-512", 64)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 1024 bits and output size of 384 bits
     */
    public object Skein1024_384 : Algorithm("Skein-1024-384", 128)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 1024 bits and output size of 512 bits
     */
    public object Skein1024_512 : Algorithm("Skein-1024-512", 128)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of 1024 bits and output size of 1024 bits
     */
    public object Skein1024_1024 : Algorithm("Skein-1024-1024", 128)

    /**
     * [Skein](https://www.schneier.com/academic/skein/) with internal state of [blockSizeBits] bits and output size of [outputSizeBits] bits
     */
    public open class Skein(internal val blockSizeBits: Int, internal val outputSizeBits: Int) :
        Algorithm("Skein-$blockSizeBits-$outputSizeBits", blockSizeBits shr 3) {

        /**
         * [Skein] as [key]ed hash with internal state of [blockSizeBits] bits and output size of [outputSizeBits] bits
         */
        public class Keyed(
            blockSizeBits: Int,
            outputSizeBits: Int,
            internal val key: ByteArray,
        ) : Skein(blockSizeBits, outputSizeBits)
    }

    /**
     * [SM3](https://en.wikipedia.org/wiki/SM3_(hash_function)) with output size of 256 bits
     */
    public object SM3 : Algorithm("SM3", 64)

    /**
     * [Tiger](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) with output size of 192 bits
     */
    public object Tiger : Algorithm("Tiger", 64)

    /**
     * [Tiger2](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) with output size of 192 bits
     */
    public object Tiger2 : Algorithm("Tiger2", 64)

    /**
     * Latest version of [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(hash_function)) with output size of 512 bits
     */
    public object Whirlpool : Algorithm("Whirlpool", 64)

    /**
     * Original version of [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(hash_function)) with output size of 512 bits
     */
    public object Whirlpool0 : Algorithm("Whirlpool-0", 64)

    /**
     * First version of [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(hash_function)) with output size of 512 bits
     */
    public object WhirlpoolT : Algorithm("Whirlpool-T", 64)

    /**
     * Create a [Digest] of the [Algorithm] for creating hashes
     */
    public fun createDigest(): Digest<*> = CoreDigest.create(this)

    /**
     * Create a hash of [input] using the [Algorithm]
     */
    public fun hash(input: ByteArray): ByteArray = createDigest().digest(input)
}
