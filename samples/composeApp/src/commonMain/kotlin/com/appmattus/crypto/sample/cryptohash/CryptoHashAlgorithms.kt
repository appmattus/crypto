/*
 * Copyright 2026 Appmattus Limited
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

package com.appmattus.crypto.sample.cryptohash

import com.appmattus.crypto.Adler
import com.appmattus.crypto.Blake
import com.appmattus.crypto.Blake2
import com.appmattus.crypto.Blake3
import com.appmattus.crypto.Bmw
import com.appmattus.crypto.Crc
import com.appmattus.crypto.CubeHash
import com.appmattus.crypto.Echo
import com.appmattus.crypto.Fugue
import com.appmattus.crypto.Groestl
import com.appmattus.crypto.Hamsi
import com.appmattus.crypto.Haraka
import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Haval
import com.appmattus.crypto.Jh
import com.appmattus.crypto.Keccak
import com.appmattus.crypto.Kupyna
import com.appmattus.crypto.Luffa
import com.appmattus.crypto.Md
import com.appmattus.crypto.Panama
import com.appmattus.crypto.RadioGatun
import com.appmattus.crypto.RipeMd
import com.appmattus.crypto.Sha2
import com.appmattus.crypto.Sha3
import com.appmattus.crypto.Shabal
import com.appmattus.crypto.Shavite
import com.appmattus.crypto.Simd
import com.appmattus.crypto.Skein
import com.appmattus.crypto.Sm3
import com.appmattus.crypto.Sp800185
import com.appmattus.crypto.Streebog
import com.appmattus.crypto.Tiger
import com.appmattus.crypto.Whirlpool

internal val cryptoHashAlgorithms: Map<String, HashAlgorithm> = mapOf(
    "Adler32" to Adler.adler32,
    "BLAKE-512" to Blake.blake512,
    "Blake2b-512" to Blake2.blake2b(512),
    "Blake2s-256" to Blake2.blake2s(256),
    "Blake3-256" to Blake3.blake3(),
    "BMW-512" to Bmw.bmw512,
    "CRC32B" to Crc.crc32b,
    "cSHAKE256" to Sp800185.cshake256(),
    "CubeHash-512" to CubeHash.cubeHash512,
    "Kupyna-512" to Kupyna.kupyna512,
    "ECHO-512" to Echo.echo512,
    "Fugue-512" to Fugue.fugue512,
    "GOST3411-2012-512" to Streebog.streebog512,
    "Groestl-512" to Groestl.groestl512,
    "Hamsi-512" to Hamsi.hamsi512,
    "Haraka-512" to Haraka.haraka512,
    "HAVAL-3-256" to Haval.haval3_256,
    "JH-512" to Jh.jh512,
    "Keccak-512" to Keccak.keccak512,
    "Luffa-512" to Luffa.luffa512,
    "MD5" to Md.md5,
    "PANAMA" to Panama.panama,
    "RadioGatún[64]" to RadioGatun.radioGatun64,
    "RipeMD256" to RipeMd.ripeMd256,
    "SHA-512/256" to Sha2.sha512_256,
    "SHA3-512" to Sha3.sha3_512,
    "Shabal-512" to Shabal.shabal512,
    "SHAKE256" to Sha3.shake256,
    "SHAvite-512" to Shavite.shavite512,
    "SIMD-512" to Simd.simd512,
    "Skein-1024-512" to Skein.skein1024_512,
    "SM3" to Sm3.sm3,
    "Tiger" to Tiger.tiger,
    "Whirlpool" to Whirlpool.whirlpool
)
