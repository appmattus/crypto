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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Adler
import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.CRC
import com.appmattus.crypto.Digest
import com.appmattus.crypto.Komihash
import com.appmattus.crypto.MetroHash
import com.appmattus.crypto.MurmurHash
import com.appmattus.crypto.RadioGatun
import com.appmattus.crypto.Rapidhash
import com.appmattus.crypto.Tiger
import com.appmattus.crypto.Wyhash
import com.appmattus.crypto.XXHash
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
import com.appmattus.crypto.internal.core.SipHash
import com.appmattus.crypto.internal.core.SkeinBouncycastleCore
import com.appmattus.crypto.internal.core.blake3.Blake3
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411_2012_256
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411_2012_512
import com.appmattus.crypto.internal.core.bouncycastle.Kupyna
import com.appmattus.crypto.internal.core.bouncycastle.ascon.Ascon
import com.appmattus.crypto.internal.core.bouncycastle.blake2.Blake2b
import com.appmattus.crypto.internal.core.bouncycastle.blake2.Blake2s
import com.appmattus.crypto.internal.core.bouncycastle.haraka.Haraka256_256
import com.appmattus.crypto.internal.core.bouncycastle.haraka.Haraka512_256
import com.appmattus.crypto.internal.core.bouncycastle.kangaroo.KangarooTwelve
import com.appmattus.crypto.internal.core.bouncycastle.shake.CSHAKEDigest
import com.appmattus.crypto.internal.core.bouncycastle.shake.SHAKEDigest
import com.appmattus.crypto.internal.core.bouncycastle.sp800185.KMAC
import com.appmattus.crypto.internal.core.bouncycastle.sp800185.ParallelHash
import com.appmattus.crypto.internal.core.bouncycastle.sp800185.TupleHash
import com.appmattus.crypto.internal.core.city.CityHash128
import com.appmattus.crypto.internal.core.city.CityHash32
import com.appmattus.crypto.internal.core.city.CityHash64
import com.appmattus.crypto.internal.core.city.CityHashCrc128
import com.appmattus.crypto.internal.core.city.CityHashCrc256
import com.appmattus.crypto.internal.core.farm.FarmHash128
import com.appmattus.crypto.internal.core.farm.FarmHash32
import com.appmattus.crypto.internal.core.farm.FarmHash64
import com.appmattus.crypto.internal.core.google.HighwayHash
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
import com.appmattus.crypto.internal.core.sphlib.Whirlpool
import com.appmattus.crypto.internal.core.sphlib.Whirlpool0
import com.appmattus.crypto.internal.core.sphlib.WhirlpoolT
import com.appmattus.crypto.internal.core.t1ha.T1ha0_32le
import com.appmattus.crypto.internal.core.t1ha.T1ha1_le
import com.appmattus.crypto.internal.core.t1ha.T1ha2_atonce
import com.appmattus.crypto.internal.core.t1ha.T1ha2_atonce128
import com.appmattus.crypto.internal.core.t1ha.T1ha2_stream
import com.appmattus.crypto.internal.core.t1ha.T1ha2_stream128

internal object CoreDigest {

    @Suppress("LongMethod", "ComplexMethod")
    fun create(algorithm: Algorithm): Digest {
        // Every branch is an is-check, objects included. An object's class has only that one instance, so is matches
        // exactly what == would, but it's a plain type check, where == calls Algorithm.equals and, on Kotlin/JS, the
        // object's accessor. On engines without a JIT, such as Hermes, those calls made dispatching to an algorithm
        // late in this list cost more than creating its digest.
        return when (algorithm) {
            is Algorithm.Adler32 -> Adler.adler32.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.AsconHash256 -> Ascon.hash256()
            is Algorithm.AsconXof128 -> Ascon.xof128(algorithm.outputSizeBits / 8)
            is Algorithm.AsconCXof128 -> Ascon.cxof128(algorithm.customisation ?: ByteArray(0), algorithm.outputSizeBits / 8)

            is Algorithm.BLAKE224 -> BLAKE224()
            is Algorithm.BLAKE256 -> BLAKE256()
            is Algorithm.BLAKE384 -> BLAKE384()
            is Algorithm.BLAKE512 -> BLAKE512()

            is Algorithm.Blake2b_160 -> Blake2b(160)
            is Algorithm.Blake2b_256 -> Blake2b(256)
            is Algorithm.Blake2b_384 -> Blake2b(384)
            is Algorithm.Blake2b_512 -> Blake2b(512)

            is Algorithm.Blake2b -> Blake2b.create(algorithm)

            is Algorithm.Blake2s_128 -> Blake2s(128)
            is Algorithm.Blake2s_160 -> Blake2s(160)
            is Algorithm.Blake2s_224 -> Blake2s(224)
            is Algorithm.Blake2s_256 -> Blake2s(256)

            is Algorithm.Blake2s -> Blake2s.create(algorithm)

            is Algorithm.Blake3 -> Blake3(algorithm)

            is Algorithm.BMW224 -> BMW224()
            is Algorithm.BMW256 -> BMW256()
            is Algorithm.BMW384 -> BMW384()
            is Algorithm.BMW512 -> BMW512()

            is Algorithm.CityHash32 -> CityHash32()
            is Algorithm.CityHash64 -> CityHash64(algorithm)
            is Algorithm.CityHash128 -> CityHash128(algorithm)
            is Algorithm.CityHashCrc128 -> CityHashCrc128(algorithm)
            is Algorithm.CityHashCrc256 -> CityHashCrc256()

            is Algorithm.CRC32 -> CRC.crc32.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CRC32B -> CRC.crc32b.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CRC32C -> CRC.crc32c.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.cSHAKE128 -> {
                CSHAKEDigest(128, algorithm.functionName, algorithm.customisation)
            }
            is Algorithm.cSHAKE256 -> {
                CSHAKEDigest(256, algorithm.functionName, algorithm.customisation)
            }

            is Algorithm.CubeHash224 -> CubeHash224()
            is Algorithm.CubeHash256 -> CubeHash256()
            is Algorithm.CubeHash384 -> CubeHash384()
            is Algorithm.CubeHash512 -> CubeHash512()

            is Algorithm.ECHO224 -> ECHO224()
            is Algorithm.ECHO256 -> ECHO256()
            is Algorithm.ECHO384 -> ECHO384()
            is Algorithm.ECHO512 -> ECHO512()

            is Algorithm.FarmHash32 -> FarmHash32(algorithm)
            is Algorithm.FarmHash64 -> FarmHash64(algorithm)
            is Algorithm.FarmHash128 -> FarmHash128(algorithm)

            is Algorithm.Fugue224 -> Fugue224()
            is Algorithm.Fugue256 -> Fugue256()
            is Algorithm.Fugue384 -> Fugue384()
            is Algorithm.Fugue512 -> Fugue512()

            is Algorithm.GOST3411_94 -> GOST3411()
            is Algorithm.GOST3411_2012_256 -> GOST3411_2012_256()
            is Algorithm.GOST3411_2012_512 -> GOST3411_2012_512()

            is Algorithm.Groestl224 -> Groestl224()
            is Algorithm.Groestl256 -> Groestl256()
            is Algorithm.Groestl384 -> Groestl384()
            is Algorithm.Groestl512 -> Groestl512()

            is Algorithm.Hamsi224 -> Hamsi224()
            is Algorithm.Hamsi256 -> Hamsi256()
            is Algorithm.Hamsi384 -> Hamsi384()
            is Algorithm.Hamsi512 -> Hamsi512()

            is Algorithm.Haraka256_256 -> Haraka256_256()
            is Algorithm.Haraka512_256 -> Haraka512_256()

            is Algorithm.HAVAL_3_128 -> HAVALCore(128, 3)
            is Algorithm.HAVAL_3_160 -> HAVALCore(160, 3)
            is Algorithm.HAVAL_3_192 -> HAVALCore(192, 3)
            is Algorithm.HAVAL_3_224 -> HAVALCore(224, 3)
            is Algorithm.HAVAL_3_256 -> HAVALCore(256, 3)
            is Algorithm.HAVAL_4_128 -> HAVALCore(128, 4)
            is Algorithm.HAVAL_4_160 -> HAVALCore(160, 4)
            is Algorithm.HAVAL_4_192 -> HAVALCore(192, 4)
            is Algorithm.HAVAL_4_224 -> HAVALCore(224, 4)
            is Algorithm.HAVAL_4_256 -> HAVALCore(256, 4)
            is Algorithm.HAVAL_5_128 -> HAVALCore(128, 5)
            is Algorithm.HAVAL_5_160 -> HAVALCore(160, 5)
            is Algorithm.HAVAL_5_192 -> HAVALCore(192, 5)
            is Algorithm.HAVAL_5_224 -> HAVALCore(224, 5)
            is Algorithm.HAVAL_5_256 -> HAVALCore(256, 5)

            is Algorithm.HighwayHash64 -> HighwayHash(algorithm.key, 64)
            is Algorithm.HighwayHash128 -> HighwayHash(algorithm.key, 128)
            is Algorithm.HighwayHash256 -> HighwayHash(algorithm.key, 256)

            is Algorithm.JH224 -> JH224()
            is Algorithm.JH256 -> JH256()
            is Algorithm.JH384 -> JH384()
            is Algorithm.JH512 -> JH512()

            is Algorithm.Keccak224 -> Keccak224()
            is Algorithm.Keccak256 -> Keccak256()
            is Algorithm.Keccak288 -> Keccak288()
            is Algorithm.Keccak384 -> Keccak384()
            is Algorithm.Keccak512 -> Keccak512()

            is Algorithm.KMAC128 -> KMAC(128, algorithm.key, algorithm.customisation, algorithm.outputSizeBits / 8)
            is Algorithm.KMAC256 -> KMAC(256, algorithm.key, algorithm.customisation, algorithm.outputSizeBits / 8)

            is Algorithm.Komihash -> Komihash.komihash(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Kupyna_256 -> Kupyna(256)
            is Algorithm.Kupyna_384 -> Kupyna(384)
            is Algorithm.Kupyna_512 -> Kupyna(512)

            is Algorithm.KT128 -> KangarooTwelve(128, algorithm.customisation, algorithm.outputSizeBits / 8)
            is Algorithm.KT256 -> KangarooTwelve(256, algorithm.customisation, algorithm.outputSizeBits / 8)

            is Algorithm.Luffa224 -> Luffa224()
            is Algorithm.Luffa256 -> Luffa256()
            is Algorithm.Luffa384 -> Luffa384()
            is Algorithm.Luffa512 -> Luffa512()

            is Algorithm.MetroHash64 -> MetroHash.metroHash64(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MetroHash128 -> MetroHash.metroHash128(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.MD2 -> MD2()
            is Algorithm.MD4 -> MD4()
            is Algorithm.MD5 -> MD5()

            is Algorithm.MurmurHash1 -> MurmurHash.murmurHash1(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash2 -> MurmurHash.murmurHash2(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash64A -> MurmurHash.murmurHash64A(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash64B -> MurmurHash.murmurHash64B(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.MurmurHash2A -> MurmurHash.murmurHash2A(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.MurmurHash3_X86_32 -> MurmurHash.murmurHash3_x86_32(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash3_X86_128 -> MurmurHash.murmurHash3_x86_128(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash3_X64_128 -> MurmurHash.murmurHash3_x64_128(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.PANAMA -> PANAMA()

            is Algorithm.ParallelHash128 -> {
                ParallelHash(128, algorithm.blockSize, algorithm.customisation, algorithm.outputSizeBits / 8)
            }
            is Algorithm.ParallelHash256 -> {
                ParallelHash(256, algorithm.blockSize, algorithm.customisation, algorithm.outputSizeBits / 8)
            }

            is Algorithm.RadioGatun32 -> RadioGatun.radioGatun32.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RadioGatun64 -> RadioGatun.radioGatun64.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Rapidhash -> Rapidhash.rapidhash(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RapidhashMicro -> Rapidhash.rapidhashMicro(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RapidhashNano -> Rapidhash.rapidhashNano(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.RipeMD -> RipeMD()
            is Algorithm.RipeMD128 -> RipeMD128()
            is Algorithm.RipeMD160 -> RipeMD160()
            is Algorithm.RipeMD256 -> RipeMD256()
            is Algorithm.RipeMD320 -> RipeMD320()

            is Algorithm.SHA_0 -> SHA0()
            is Algorithm.SHA_1 -> SHA1()
            is Algorithm.SHA_224 -> SHA224()
            is Algorithm.SHA_256 -> SHA256()
            is Algorithm.SHA_384 -> SHA384()
            is Algorithm.SHA_512 -> SHA512()
            is Algorithm.SHA_512_224 -> SHA512_224()
            is Algorithm.SHA_512_256 -> SHA512_256()

            is Algorithm.SHA3_224 -> SHA3_224()
            is Algorithm.SHA3_256 -> SHA3_256()
            is Algorithm.SHA3_384 -> SHA3_384()
            is Algorithm.SHA3_512 -> SHA3_512()

            is Algorithm.Shabal192 -> ShabalGeneric(192)
            is Algorithm.Shabal224 -> ShabalGeneric(224)
            is Algorithm.Shabal256 -> ShabalGeneric(256)
            is Algorithm.Shabal384 -> ShabalGeneric(384)
            is Algorithm.Shabal512 -> ShabalGeneric(512)

            is Algorithm.SHAKE128 -> SHAKEDigest(128)
            is Algorithm.SHAKE256 -> SHAKEDigest(256)

            is Algorithm.SHAvite224 -> SHAvite224()
            is Algorithm.SHAvite256 -> SHAvite256()
            is Algorithm.SHAvite384 -> SHAvite384()
            is Algorithm.SHAvite512 -> SHAvite512()

            is Algorithm.SIMD224 -> SIMD224()
            is Algorithm.SIMD256 -> SIMD256()
            is Algorithm.SIMD384 -> SIMD384()
            is Algorithm.SIMD512 -> SIMD512()

            is Algorithm.SipHash -> SipHash(algorithm.key, algorithm.compressionRounds, algorithm.finalizationRounds, 64)
            is Algorithm.SipHash128 -> SipHash(algorithm.key, algorithm.compressionRounds, algorithm.finalizationRounds, 128)

            is Algorithm.Skein256_128 -> SkeinBouncycastleCore(256, 128)
            is Algorithm.Skein256_160 -> SkeinBouncycastleCore(256, 160)
            is Algorithm.Skein256_224 -> SkeinBouncycastleCore(256, 224)
            is Algorithm.Skein256_256 -> SkeinBouncycastleCore(256, 256)
            is Algorithm.Skein512_128 -> SkeinBouncycastleCore(512, 128)
            is Algorithm.Skein512_160 -> SkeinBouncycastleCore(512, 160)
            is Algorithm.Skein512_224 -> SkeinBouncycastleCore(512, 224)
            is Algorithm.Skein512_256 -> SkeinBouncycastleCore(512, 256)
            is Algorithm.Skein512_384 -> SkeinBouncycastleCore(512, 384)
            is Algorithm.Skein512_512 -> SkeinBouncycastleCore(512, 512)
            is Algorithm.Skein1024_384 -> SkeinBouncycastleCore(1024, 384)
            is Algorithm.Skein1024_512 -> SkeinBouncycastleCore(1024, 512)
            is Algorithm.Skein1024_1024 -> SkeinBouncycastleCore(1024, 1024)

            is Algorithm.Skein -> SkeinBouncycastleCore.create(algorithm)

            is Algorithm.SM3 -> SM3()

            is Algorithm.T1ha0_32le -> T1ha0_32le(algorithm.seed)
            is Algorithm.T1ha1_le -> T1ha1_le(algorithm.seed)
            is Algorithm.T1ha2_AtOnce -> T1ha2_atonce(algorithm.seed)
            is Algorithm.T1ha2_AtOnce128 -> T1ha2_atonce128(algorithm.seed)
            is Algorithm.T1ha2_Stream -> T1ha2_stream(algorithm.seedX, algorithm.seedY)
            is Algorithm.T1ha2_Stream128 -> T1ha2_stream128(algorithm.seedX, algorithm.seedY)

            is Algorithm.Tiger -> Tiger.tiger.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Tiger2 -> Tiger.tiger2.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.TupleHash128 -> TupleHash(128, algorithm.customisation, algorithm.outputSizeBits / 8)
            is Algorithm.TupleHash256 -> TupleHash(256, algorithm.customisation, algorithm.outputSizeBits / 8)

            is Algorithm.Whirlpool -> Whirlpool()
            is Algorithm.Whirlpool0 -> Whirlpool0()
            is Algorithm.WhirlpoolT -> WhirlpoolT()

            is Algorithm.Wyhash -> Wyhash.wyhash64(algorithm.seed, algorithm.secret, algorithm.extraProtection).newHasher()
                .toDigest(algorithm.blockLength)
            is Algorithm.Wyhash32 -> Wyhash.wyhash32(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.XXHash32 -> XXHash.xxh32(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.XXHash64 -> XXHash.xxh64(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.XXH3_64 -> when (algorithm) {
                is Algorithm.XXH3_64.Seeded -> XXHash.xxh3_64(algorithm.seed)
                is Algorithm.XXH3_64.Secret -> XXHash.xxh3_64(algorithm.secret)
                else -> XXHash.xxh3_64()
            }.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.XXH3_128 -> when (algorithm) {
                is Algorithm.XXH3_128.Seeded -> XXHash.xxh3_128(algorithm.seed)
                is Algorithm.XXH3_128.Secret -> XXHash.xxh3_128(algorithm.secret)
                else -> XXHash.xxh3_128()
            }.newHasher().toDigest(algorithm.blockLength)
        }
    }
}
