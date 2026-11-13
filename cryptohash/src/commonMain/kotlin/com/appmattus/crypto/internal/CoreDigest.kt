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
import com.appmattus.crypto.Ascon
import com.appmattus.crypto.Blake
import com.appmattus.crypto.Blake2
import com.appmattus.crypto.Blake3
import com.appmattus.crypto.CRC
import com.appmattus.crypto.CityHash
import com.appmattus.crypto.Digest
import com.appmattus.crypto.FarmHash
import com.appmattus.crypto.Gost
import com.appmattus.crypto.Haraka
import com.appmattus.crypto.Haval
import com.appmattus.crypto.HighwayHash
import com.appmattus.crypto.KangarooTwelve
import com.appmattus.crypto.Keccak
import com.appmattus.crypto.Komihash
import com.appmattus.crypto.Kupyna
import com.appmattus.crypto.MD
import com.appmattus.crypto.MetroHash
import com.appmattus.crypto.MurmurHash
import com.appmattus.crypto.Panama
import com.appmattus.crypto.RadioGatun
import com.appmattus.crypto.Rapidhash
import com.appmattus.crypto.RipeMD
import com.appmattus.crypto.SHA3
import com.appmattus.crypto.SM3
import com.appmattus.crypto.SP800185
import com.appmattus.crypto.SipHash
import com.appmattus.crypto.Streebog
import com.appmattus.crypto.T1ha
import com.appmattus.crypto.Tiger
import com.appmattus.crypto.Whirlpool
import com.appmattus.crypto.Wyhash
import com.appmattus.crypto.XXHash
import com.appmattus.crypto.internal.core.SHA512_224
import com.appmattus.crypto.internal.core.SHA512_256
import com.appmattus.crypto.internal.core.SkeinBouncycastleCore
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
import com.appmattus.crypto.internal.core.sphlib.Hamsi224
import com.appmattus.crypto.internal.core.sphlib.Hamsi256
import com.appmattus.crypto.internal.core.sphlib.Hamsi384
import com.appmattus.crypto.internal.core.sphlib.Hamsi512
import com.appmattus.crypto.internal.core.sphlib.JH224
import com.appmattus.crypto.internal.core.sphlib.JH256
import com.appmattus.crypto.internal.core.sphlib.JH384
import com.appmattus.crypto.internal.core.sphlib.JH512
import com.appmattus.crypto.internal.core.sphlib.Luffa224
import com.appmattus.crypto.internal.core.sphlib.Luffa256
import com.appmattus.crypto.internal.core.sphlib.Luffa384
import com.appmattus.crypto.internal.core.sphlib.Luffa512
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

internal object CoreDigest {

    @Suppress("LongMethod", "ComplexMethod")
    fun create(algorithm: Algorithm): Digest {
        // Every branch is an is-check, objects included. An object's class has only that one instance, so is matches
        // exactly what == would, but it's a plain type check, where == calls Algorithm.equals and, on Kotlin/JS, the
        // object's accessor. On engines without a JIT, such as Hermes, those calls made dispatching to an algorithm
        // late in this list cost more than creating its digest.
        return when (algorithm) {
            is Algorithm.Adler32 -> Adler.adler32.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.AsconHash256 -> Ascon.hash256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.AsconXof128 -> Ascon.xof128(algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.AsconCXof128 -> {
                Ascon.cxof128(algorithm.customisation, algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            }

            is Algorithm.BLAKE224 -> Blake.blake224.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.BLAKE256 -> Blake.blake256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.BLAKE384 -> Blake.blake384.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.BLAKE512 -> Blake.blake512.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Blake2b_160 -> Blake2.blake2b(160).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Blake2b_256 -> Blake2.blake2b(256).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Blake2b_384 -> Blake2.blake2b(384).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Blake2b_512 -> Blake2.blake2b(512).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Blake2b -> when (algorithm) {
                is Algorithm.Blake2b.Keyed -> Blake2.blake2bKeyed(
                    algorithm.key,
                    algorithm.salt,
                    algorithm.personalisation,
                    algorithm.outputSizeBits
                )
                else -> Blake2.blake2b(algorithm.outputSizeBits)
            }.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Blake2s_128 -> Blake2.blake2s(128).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Blake2s_160 -> Blake2.blake2s(160).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Blake2s_224 -> Blake2.blake2s(224).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Blake2s_256 -> Blake2.blake2s(256).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Blake2s -> when (algorithm) {
                is Algorithm.Blake2s.Keyed -> Blake2.blake2sKeyed(
                    algorithm.key,
                    algorithm.salt,
                    algorithm.personalisation,
                    algorithm.outputSizeBits
                )
                else -> Blake2.blake2s(algorithm.outputSizeBits)
            }.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Blake3 -> when (algorithm) {
                is Algorithm.Blake3.Keyed -> Blake3.blake3Keyed(algorithm.key, algorithm.digestLength)
                is Algorithm.Blake3.DeriveKey -> Blake3.blake3DeriveKey(algorithm.context, algorithm.digestLength)
                else -> Blake3.blake3(algorithm.digestLength)
            }.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.BMW224 -> BMW224()
            is Algorithm.BMW256 -> BMW256()
            is Algorithm.BMW384 -> BMW384()
            is Algorithm.BMW512 -> BMW512()

            is Algorithm.CityHash32 -> CityHash.cityHash32.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CityHash64 -> when (algorithm) {
                is Algorithm.CityHash64.Seed -> CityHash.cityHash64(algorithm.seed)
                is Algorithm.CityHash64.Seeds -> CityHash.cityHash64(algorithm.seed1, algorithm.seed2)
                else -> CityHash.cityHash64()
            }.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CityHash128 -> when (algorithm) {
                is Algorithm.CityHash128.Seed -> CityHash.cityHash128(algorithm.seedLow, algorithm.seedHigh)
                else -> CityHash.cityHash128()
            }.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CityHashCrc128 -> when (algorithm) {
                is Algorithm.CityHashCrc128.Seed -> CityHash.cityHashCrc128(algorithm.seedLow, algorithm.seedHigh)
                else -> CityHash.cityHashCrc128()
            }.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CityHashCrc256 -> CityHash.cityHashCrc256.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.CRC32 -> CRC.crc32.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CRC32B -> CRC.crc32b.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.CRC32C -> CRC.crc32c.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.cSHAKE128 -> {
                SP800185.cshake128(algorithm.customisation, algorithm.functionName).newHasher().toDigest(algorithm.blockLength)
            }
            is Algorithm.cSHAKE256 -> {
                SP800185.cshake256(algorithm.customisation, algorithm.functionName).newHasher().toDigest(algorithm.blockLength)
            }

            is Algorithm.CubeHash224 -> CubeHash224()
            is Algorithm.CubeHash256 -> CubeHash256()
            is Algorithm.CubeHash384 -> CubeHash384()
            is Algorithm.CubeHash512 -> CubeHash512()

            is Algorithm.ECHO224 -> ECHO224()
            is Algorithm.ECHO256 -> ECHO256()
            is Algorithm.ECHO384 -> ECHO384()
            is Algorithm.ECHO512 -> ECHO512()

            is Algorithm.FarmHash32 -> when (algorithm) {
                is Algorithm.FarmHash32.Seed -> FarmHash.farmHash32(algorithm.seed)
                else -> FarmHash.farmHash32()
            }.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.FarmHash64 -> when (algorithm) {
                is Algorithm.FarmHash64.Seed -> FarmHash.farmHash64(algorithm.seed)
                is Algorithm.FarmHash64.Seeds -> FarmHash.farmHash64(algorithm.seed1, algorithm.seed2)
                else -> FarmHash.farmHash64()
            }.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.FarmHash128 -> when (algorithm) {
                is Algorithm.FarmHash128.Seed -> FarmHash.farmHash128(algorithm.seedLow, algorithm.seedHigh)
                else -> FarmHash.farmHash128()
            }.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Fugue224 -> Fugue224()
            is Algorithm.Fugue256 -> Fugue256()
            is Algorithm.Fugue384 -> Fugue384()
            is Algorithm.Fugue512 -> Fugue512()

            is Algorithm.GOST3411_94 -> Gost.gost3411_94.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.GOST3411_2012_256 -> Streebog.streebog256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.GOST3411_2012_512 -> Streebog.streebog512.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Groestl224 -> Groestl224()
            is Algorithm.Groestl256 -> Groestl256()
            is Algorithm.Groestl384 -> Groestl384()
            is Algorithm.Groestl512 -> Groestl512()

            is Algorithm.Hamsi224 -> Hamsi224()
            is Algorithm.Hamsi256 -> Hamsi256()
            is Algorithm.Hamsi384 -> Hamsi384()
            is Algorithm.Hamsi512 -> Hamsi512()

            is Algorithm.Haraka256_256 -> Haraka.haraka256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Haraka512_256 -> Haraka.haraka512.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.HAVAL_3_128 -> Haval.haval3_128.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_3_160 -> Haval.haval3_160.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_3_192 -> Haval.haval3_192.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_3_224 -> Haval.haval3_224.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_3_256 -> Haval.haval3_256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_4_128 -> Haval.haval4_128.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_4_160 -> Haval.haval4_160.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_4_192 -> Haval.haval4_192.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_4_224 -> Haval.haval4_224.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_4_256 -> Haval.haval4_256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_5_128 -> Haval.haval5_128.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_5_160 -> Haval.haval5_160.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_5_192 -> Haval.haval5_192.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_5_224 -> Haval.haval5_224.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HAVAL_5_256 -> Haval.haval5_256.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.HighwayHash64 -> HighwayHash.highwayHash64(algorithm.key).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HighwayHash128 -> HighwayHash.highwayHash128(algorithm.key).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.HighwayHash256 -> HighwayHash.highwayHash256(algorithm.key).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.JH224 -> JH224()
            is Algorithm.JH256 -> JH256()
            is Algorithm.JH384 -> JH384()
            is Algorithm.JH512 -> JH512()

            is Algorithm.Keccak224 -> Keccak.keccak224.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Keccak256 -> Keccak.keccak256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Keccak288 -> Keccak.keccak288.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Keccak384 -> Keccak.keccak384.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Keccak512 -> Keccak.keccak512.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.KMAC128 -> {
                SP800185.kmac128(algorithm.key, algorithm.customisation, algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            }
            is Algorithm.KMAC256 -> {
                SP800185.kmac256(algorithm.key, algorithm.customisation, algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            }

            is Algorithm.Komihash -> Komihash.komihash(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Kupyna_256 -> Kupyna.kupyna256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Kupyna_384 -> Kupyna.kupyna384.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Kupyna_512 -> Kupyna.kupyna512.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.KT128 -> {
                KangarooTwelve.kt128(algorithm.customisation, algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            }
            is Algorithm.KT256 -> {
                KangarooTwelve.kt256(algorithm.customisation, algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            }

            is Algorithm.Luffa224 -> Luffa224()
            is Algorithm.Luffa256 -> Luffa256()
            is Algorithm.Luffa384 -> Luffa384()
            is Algorithm.Luffa512 -> Luffa512()

            is Algorithm.MetroHash64 -> MetroHash.metroHash64(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MetroHash128 -> MetroHash.metroHash128(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.MD2 -> MD.md2.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MD4 -> MD.md4.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MD5 -> MD.md5.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.MurmurHash1 -> MurmurHash.murmurHash1(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash2 -> MurmurHash.murmurHash2(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash64A -> MurmurHash.murmurHash64A(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash64B -> MurmurHash.murmurHash64B(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.MurmurHash2A -> MurmurHash.murmurHash2A(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.MurmurHash3_X86_32 -> MurmurHash.murmurHash3_x86_32(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash3_X86_128 -> MurmurHash.murmurHash3_x86_128(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.MurmurHash3_X64_128 -> MurmurHash.murmurHash3_x64_128(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.PANAMA -> Panama.panama.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.ParallelHash128 -> {
                SP800185.parallelHash128(
                    algorithm.blockSize,
                    algorithm.customisation,
                    algorithm.outputSizeBits
                ).newHasher().toDigest(algorithm.blockLength)
            }
            is Algorithm.ParallelHash256 -> {
                SP800185.parallelHash256(
                    algorithm.blockSize,
                    algorithm.customisation,
                    algorithm.outputSizeBits
                ).newHasher().toDigest(algorithm.blockLength)
            }

            is Algorithm.RadioGatun32 -> RadioGatun.radioGatun32.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RadioGatun64 -> RadioGatun.radioGatun64.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Rapidhash -> Rapidhash.rapidhash(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RapidhashMicro -> Rapidhash.rapidhashMicro(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RapidhashNano -> Rapidhash.rapidhashNano(algorithm.seed).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.RipeMD -> RipeMD.ripeMD.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RipeMD128 -> RipeMD.ripeMD128.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RipeMD160 -> RipeMD.ripeMD160.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RipeMD256 -> RipeMD.ripeMD256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.RipeMD320 -> RipeMD.ripeMD320.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.SHA_0 -> SHA0()
            is Algorithm.SHA_1 -> SHA1()
            is Algorithm.SHA_224 -> SHA224()
            is Algorithm.SHA_256 -> SHA256()
            is Algorithm.SHA_384 -> SHA384()
            is Algorithm.SHA_512 -> SHA512()
            is Algorithm.SHA_512_224 -> SHA512_224()
            is Algorithm.SHA_512_256 -> SHA512_256()

            is Algorithm.SHA3_224 -> SHA3.sha3_224.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.SHA3_256 -> SHA3.sha3_256.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.SHA3_384 -> SHA3.sha3_384.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.SHA3_512 -> SHA3.sha3_512.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Shabal192 -> ShabalGeneric(192)
            is Algorithm.Shabal224 -> ShabalGeneric(224)
            is Algorithm.Shabal256 -> ShabalGeneric(256)
            is Algorithm.Shabal384 -> ShabalGeneric(384)
            is Algorithm.Shabal512 -> ShabalGeneric(512)

            is Algorithm.SHAKE128 -> SHA3.shake128.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.SHAKE256 -> SHA3.shake256.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.SHAvite224 -> SHAvite224()
            is Algorithm.SHAvite256 -> SHAvite256()
            is Algorithm.SHAvite384 -> SHAvite384()
            is Algorithm.SHAvite512 -> SHAvite512()

            is Algorithm.SIMD224 -> SIMD224()
            is Algorithm.SIMD256 -> SIMD256()
            is Algorithm.SIMD384 -> SIMD384()
            is Algorithm.SIMD512 -> SIMD512()

            is Algorithm.SipHash -> SipHash.sipHash(
                algorithm.key,
                algorithm.compressionRounds,
                algorithm.finalizationRounds
            ).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.SipHash128 -> SipHash.sipHash128(
                algorithm.key,
                algorithm.compressionRounds,
                algorithm.finalizationRounds
            ).newHasher().toDigest(algorithm.blockLength)

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

            is Algorithm.SM3 -> SM3.sm3.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.T1ha0_32le -> T1ha.t1ha0_32le(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.T1ha1_le -> T1ha.t1ha1_le(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.T1ha2_AtOnce -> T1ha.t1ha2AtOnce(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.T1ha2_AtOnce128 -> T1ha.t1ha2AtOnce128(algorithm.seed).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.T1ha2_Stream -> T1ha.t1ha2Stream(algorithm.seedX, algorithm.seedY).newHasher().toDigest(algorithm.blockLength)
            is Algorithm.T1ha2_Stream128 -> T1ha.t1ha2Stream128(algorithm.seedX, algorithm.seedY).newHasher().toDigest(algorithm.blockLength)

            is Algorithm.Tiger -> Tiger.tiger.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Tiger2 -> Tiger.tiger2.newHasher().toDigest(algorithm.blockLength)

            is Algorithm.TupleHash128 -> {
                SP800185.tupleHash128(algorithm.customisation, algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            }
            is Algorithm.TupleHash256 -> {
                SP800185.tupleHash256(algorithm.customisation, algorithm.outputSizeBits).newHasher().toDigest(algorithm.blockLength)
            }

            is Algorithm.Whirlpool -> Whirlpool.whirlpool.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.Whirlpool0 -> Whirlpool.whirlpool0.newHasher().toDigest(algorithm.blockLength)
            is Algorithm.WhirlpoolT -> Whirlpool.whirlpoolT.newHasher().toDigest(algorithm.blockLength)

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
