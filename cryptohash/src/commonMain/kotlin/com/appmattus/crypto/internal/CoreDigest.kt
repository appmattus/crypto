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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.Adler32
import com.appmattus.crypto.internal.core.CRC32
import com.appmattus.crypto.internal.core.Keccak288
import com.appmattus.crypto.internal.core.RipeMD256
import com.appmattus.crypto.internal.core.RipeMD320
import com.appmattus.crypto.internal.core.SHA3_224
import com.appmattus.crypto.internal.core.SHA3_256
import com.appmattus.crypto.internal.core.SHA3_384
import com.appmattus.crypto.internal.core.SHA3_512
import com.appmattus.crypto.internal.core.SHA512_224
import com.appmattus.crypto.internal.core.SHA512_256
import com.appmattus.crypto.internal.core.SM3
import com.appmattus.crypto.internal.core.SkeinBouncycastleCore
import com.appmattus.crypto.internal.core.blake3.Blake3
import com.appmattus.crypto.internal.core.bouncycastle.DSTU7564
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411_2012_256
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411_2012_512
import com.appmattus.crypto.internal.core.bouncycastle.blake2.Blake2b
import com.appmattus.crypto.internal.core.bouncycastle.blake2.Blake2s
import com.appmattus.crypto.internal.core.bouncycastle.haraka.Haraka256_256
import com.appmattus.crypto.internal.core.bouncycastle.haraka.Haraka512_256
import com.appmattus.crypto.internal.core.bouncycastle.shake.CSHAKEDigest
import com.appmattus.crypto.internal.core.bouncycastle.shake.SHAKEDigest
import com.appmattus.crypto.internal.core.sphlib.BLAKE224
import com.appmattus.crypto.internal.core.sphlib.BLAKE256
import com.appmattus.crypto.internal.core.sphlib.BLAKE384
import com.appmattus.crypto.internal.core.sphlib.BLAKE512
import com.appmattus.crypto.internal.core.sphlib.BMW224
import com.appmattus.crypto.internal.core.sphlib.BMW256
import com.appmattus.crypto.internal.core.sphlib.BMW384
import com.appmattus.crypto.internal.core.sphlib.BMW512
import com.appmattus.crypto.internal.core.sphlib.CubeHash224
import com.appmattus.crypto.internal.core.sphlib.CubeHash256
import com.appmattus.crypto.internal.core.sphlib.CubeHash384
import com.appmattus.crypto.internal.core.sphlib.CubeHash512
import com.appmattus.crypto.internal.core.sphlib.ECHO224
import com.appmattus.crypto.internal.core.sphlib.ECHO256
import com.appmattus.crypto.internal.core.sphlib.ECHO384
import com.appmattus.crypto.internal.core.sphlib.ECHO512
import com.appmattus.crypto.internal.core.sphlib.Fugue224
import com.appmattus.crypto.internal.core.sphlib.Fugue256
import com.appmattus.crypto.internal.core.sphlib.Fugue384
import com.appmattus.crypto.internal.core.sphlib.Fugue512
import com.appmattus.crypto.internal.core.sphlib.Groestl224
import com.appmattus.crypto.internal.core.sphlib.Groestl256
import com.appmattus.crypto.internal.core.sphlib.Groestl384
import com.appmattus.crypto.internal.core.sphlib.Groestl512
import com.appmattus.crypto.internal.core.sphlib.HAVALCore
import com.appmattus.crypto.internal.core.sphlib.Hamsi224
import com.appmattus.crypto.internal.core.sphlib.Hamsi256
import com.appmattus.crypto.internal.core.sphlib.Hamsi384
import com.appmattus.crypto.internal.core.sphlib.Hamsi512
import com.appmattus.crypto.internal.core.sphlib.JH224
import com.appmattus.crypto.internal.core.sphlib.JH256
import com.appmattus.crypto.internal.core.sphlib.JH384
import com.appmattus.crypto.internal.core.sphlib.JH512
import com.appmattus.crypto.internal.core.sphlib.Keccak224
import com.appmattus.crypto.internal.core.sphlib.Keccak256
import com.appmattus.crypto.internal.core.sphlib.Keccak384
import com.appmattus.crypto.internal.core.sphlib.Keccak512
import com.appmattus.crypto.internal.core.sphlib.Luffa224
import com.appmattus.crypto.internal.core.sphlib.Luffa256
import com.appmattus.crypto.internal.core.sphlib.Luffa384
import com.appmattus.crypto.internal.core.sphlib.Luffa512
import com.appmattus.crypto.internal.core.sphlib.MD2
import com.appmattus.crypto.internal.core.sphlib.MD4
import com.appmattus.crypto.internal.core.sphlib.MD5
import com.appmattus.crypto.internal.core.sphlib.PANAMA
import com.appmattus.crypto.internal.core.sphlib.RadioGatun32
import com.appmattus.crypto.internal.core.sphlib.RadioGatun64
import com.appmattus.crypto.internal.core.sphlib.RipeMD
import com.appmattus.crypto.internal.core.sphlib.RipeMD128
import com.appmattus.crypto.internal.core.sphlib.RipeMD160
import com.appmattus.crypto.internal.core.sphlib.SHA0
import com.appmattus.crypto.internal.core.sphlib.SHA1
import com.appmattus.crypto.internal.core.sphlib.SHA224
import com.appmattus.crypto.internal.core.sphlib.SHA256
import com.appmattus.crypto.internal.core.sphlib.SHA384
import com.appmattus.crypto.internal.core.sphlib.SHA512
import com.appmattus.crypto.internal.core.sphlib.SHAvite224
import com.appmattus.crypto.internal.core.sphlib.SHAvite256
import com.appmattus.crypto.internal.core.sphlib.SHAvite384
import com.appmattus.crypto.internal.core.sphlib.SHAvite512
import com.appmattus.crypto.internal.core.sphlib.SIMD224
import com.appmattus.crypto.internal.core.sphlib.SIMD256
import com.appmattus.crypto.internal.core.sphlib.SIMD384
import com.appmattus.crypto.internal.core.sphlib.SIMD512
import com.appmattus.crypto.internal.core.sphlib.ShabalGeneric
import com.appmattus.crypto.internal.core.sphlib.Tiger
import com.appmattus.crypto.internal.core.sphlib.Tiger2
import com.appmattus.crypto.internal.core.sphlib.Whirlpool
import com.appmattus.crypto.internal.core.sphlib.Whirlpool0
import com.appmattus.crypto.internal.core.sphlib.WhirlpoolT

internal object CoreDigest {

    @Suppress("MagicNumber", "LongMethod", "ComplexMethod")
    fun create(algorithm: Algorithm): Digest<*> {
        return when (algorithm) {
            Algorithm.Adler32 -> Adler32()

            Algorithm.BLAKE224 -> BLAKE224()
            Algorithm.BLAKE256 -> BLAKE256()
            Algorithm.BLAKE384 -> BLAKE384()
            Algorithm.BLAKE512 -> BLAKE512()

            Algorithm.Blake2b_160 -> Blake2b(160)
            Algorithm.Blake2b_256 -> Blake2b(256)
            Algorithm.Blake2b_384 -> Blake2b(384)
            Algorithm.Blake2b_512 -> Blake2b(512)

            is Algorithm.Blake2b -> Blake2b.create(algorithm)

            Algorithm.Blake2s_128 -> Blake2s(128)
            Algorithm.Blake2s_160 -> Blake2s(160)
            Algorithm.Blake2s_224 -> Blake2s(224)
            Algorithm.Blake2s_256 -> Blake2s(256)

            is Algorithm.Blake2s -> Blake2s.create(algorithm)

            is Algorithm.Blake3 -> Blake3(algorithm)

            Algorithm.BMW224 -> BMW224()
            Algorithm.BMW256 -> BMW256()
            Algorithm.BMW384 -> BMW384()
            Algorithm.BMW512 -> BMW512()

            Algorithm.CRC32 -> CRC32()

            is Algorithm.cSHAKE128 -> {
                CSHAKEDigest(128, algorithm.functionName, algorithm.customisation)
            }
            is Algorithm.cSHAKE256 -> {
                CSHAKEDigest(256, algorithm.functionName, algorithm.customisation)
            }

            Algorithm.CubeHash224 -> CubeHash224()
            Algorithm.CubeHash256 -> CubeHash256()
            Algorithm.CubeHash384 -> CubeHash384()
            Algorithm.CubeHash512 -> CubeHash512()

            Algorithm.DSTU7564_256 -> DSTU7564(256)
            Algorithm.DSTU7564_384 -> DSTU7564(384)
            Algorithm.DSTU7564_512 -> DSTU7564(512)

            Algorithm.ECHO224 -> ECHO224()
            Algorithm.ECHO256 -> ECHO256()
            Algorithm.ECHO384 -> ECHO384()
            Algorithm.ECHO512 -> ECHO512()

            Algorithm.Fugue224 -> Fugue224()
            Algorithm.Fugue256 -> Fugue256()
            Algorithm.Fugue384 -> Fugue384()
            Algorithm.Fugue512 -> Fugue512()

            Algorithm.GOST3411_94 -> GOST3411()
            Algorithm.GOST3411_2012_256 -> GOST3411_2012_256()
            Algorithm.GOST3411_2012_512 -> GOST3411_2012_512()

            Algorithm.Groestl224 -> Groestl224()
            Algorithm.Groestl256 -> Groestl256()
            Algorithm.Groestl384 -> Groestl384()
            Algorithm.Groestl512 -> Groestl512()

            Algorithm.Hamsi224 -> Hamsi224()
            Algorithm.Hamsi256 -> Hamsi256()
            Algorithm.Hamsi384 -> Hamsi384()
            Algorithm.Hamsi512 -> Hamsi512()

            Algorithm.Haraka256_256 -> Haraka256_256()
            Algorithm.Haraka512_256 -> Haraka512_256()

            Algorithm.HAVAL_3_128 -> HAVALCore(128, 3)
            Algorithm.HAVAL_3_160 -> HAVALCore(160, 3)
            Algorithm.HAVAL_3_192 -> HAVALCore(192, 3)
            Algorithm.HAVAL_3_224 -> HAVALCore(224, 3)
            Algorithm.HAVAL_3_256 -> HAVALCore(256, 3)
            Algorithm.HAVAL_4_128 -> HAVALCore(128, 4)
            Algorithm.HAVAL_4_160 -> HAVALCore(160, 4)
            Algorithm.HAVAL_4_192 -> HAVALCore(192, 4)
            Algorithm.HAVAL_4_224 -> HAVALCore(224, 4)
            Algorithm.HAVAL_4_256 -> HAVALCore(256, 4)
            Algorithm.HAVAL_5_128 -> HAVALCore(128, 5)
            Algorithm.HAVAL_5_160 -> HAVALCore(160, 5)
            Algorithm.HAVAL_5_192 -> HAVALCore(192, 5)
            Algorithm.HAVAL_5_224 -> HAVALCore(224, 5)
            Algorithm.HAVAL_5_256 -> HAVALCore(256, 5)

            Algorithm.JH224 -> JH224()
            Algorithm.JH256 -> JH256()
            Algorithm.JH384 -> JH384()
            Algorithm.JH512 -> JH512()

            Algorithm.Keccak224 -> Keccak224()
            Algorithm.Keccak256 -> Keccak256()
            Algorithm.Keccak288 -> Keccak288()
            Algorithm.Keccak384 -> Keccak384()
            Algorithm.Keccak512 -> Keccak512()

            Algorithm.Luffa224 -> Luffa224()
            Algorithm.Luffa256 -> Luffa256()
            Algorithm.Luffa384 -> Luffa384()
            Algorithm.Luffa512 -> Luffa512()

            Algorithm.MD2 -> MD2()
            Algorithm.MD4 -> MD4()
            Algorithm.MD5 -> MD5()

            Algorithm.PANAMA -> PANAMA()

            Algorithm.RadioGatun32 -> RadioGatun32()
            Algorithm.RadioGatun64 -> RadioGatun64()

            Algorithm.RipeMD -> RipeMD()
            Algorithm.RipeMD128 -> RipeMD128()
            Algorithm.RipeMD160 -> RipeMD160()
            Algorithm.RipeMD256 -> RipeMD256()
            Algorithm.RipeMD320 -> RipeMD320()

            Algorithm.SHA_0 -> SHA0()
            Algorithm.SHA_1 -> SHA1()
            Algorithm.SHA_224 -> SHA224()
            Algorithm.SHA_256 -> SHA256()
            Algorithm.SHA_384 -> SHA384()
            Algorithm.SHA_512 -> SHA512()
            Algorithm.SHA_512_224 -> SHA512_224()
            Algorithm.SHA_512_256 -> SHA512_256()

            Algorithm.SHA3_224 -> SHA3_224()
            Algorithm.SHA3_256 -> SHA3_256()
            Algorithm.SHA3_384 -> SHA3_384()
            Algorithm.SHA3_512 -> SHA3_512()

            Algorithm.Shabal192 -> ShabalGeneric(192)
            Algorithm.Shabal224 -> ShabalGeneric(224)
            Algorithm.Shabal256 -> ShabalGeneric(256)
            Algorithm.Shabal384 -> ShabalGeneric(384)
            Algorithm.Shabal512 -> ShabalGeneric(512)

            Algorithm.SHAKE128 -> SHAKEDigest(128)
            Algorithm.SHAKE256 -> SHAKEDigest(256)

            Algorithm.SHAvite224 -> SHAvite224()
            Algorithm.SHAvite256 -> SHAvite256()
            Algorithm.SHAvite384 -> SHAvite384()
            Algorithm.SHAvite512 -> SHAvite512()

            Algorithm.SIMD224 -> SIMD224()
            Algorithm.SIMD256 -> SIMD256()
            Algorithm.SIMD384 -> SIMD384()
            Algorithm.SIMD512 -> SIMD512()

            Algorithm.Skein256_128 -> SkeinBouncycastleCore(256, 128)
            Algorithm.Skein256_160 -> SkeinBouncycastleCore(256, 160)
            Algorithm.Skein256_224 -> SkeinBouncycastleCore(256, 224)
            Algorithm.Skein256_256 -> SkeinBouncycastleCore(256, 256)
            Algorithm.Skein512_128 -> SkeinBouncycastleCore(512, 128)
            Algorithm.Skein512_160 -> SkeinBouncycastleCore(512, 160)
            Algorithm.Skein512_224 -> SkeinBouncycastleCore(512, 224)
            Algorithm.Skein512_256 -> SkeinBouncycastleCore(512, 256)
            Algorithm.Skein512_384 -> SkeinBouncycastleCore(512, 384)
            Algorithm.Skein512_512 -> SkeinBouncycastleCore(512, 512)
            Algorithm.Skein1024_384 -> SkeinBouncycastleCore(1024, 384)
            Algorithm.Skein1024_512 -> SkeinBouncycastleCore(1024, 512)
            Algorithm.Skein1024_1024 -> SkeinBouncycastleCore(1024, 1024)

            is Algorithm.Skein -> SkeinBouncycastleCore.create(algorithm)

            Algorithm.SM3 -> SM3()

            Algorithm.Tiger -> Tiger()
            Algorithm.Tiger2 -> Tiger2()

            Algorithm.Whirlpool -> Whirlpool()
            Algorithm.Whirlpool0 -> Whirlpool0()
            Algorithm.WhirlpoolT -> WhirlpoolT()
        }
    }
}
