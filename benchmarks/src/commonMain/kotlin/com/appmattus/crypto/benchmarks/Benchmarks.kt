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

package com.appmattus.crypto.benchmarks

import com.appmattus.crypto.Adler
import com.appmattus.crypto.Blake2
import com.appmattus.crypto.Blake3
import com.appmattus.crypto.Crc
import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Komihash
import com.appmattus.crypto.Md
import com.appmattus.crypto.MurmurHash
import com.appmattus.crypto.Rapidhash
import com.appmattus.crypto.Sha1
import com.appmattus.crypto.Sha2
import com.appmattus.crypto.Sha3
import com.appmattus.crypto.T1ha
import com.appmattus.crypto.Wyhash
import com.appmattus.crypto.XxHash

/**
 * Input sizes in bytes for every benchmark: a short key, a small message and a large message
 */
internal const val SIZE_SMALL = "64"
internal const val SIZE_MEDIUM = "1024"
internal const val SIZE_LARGE = "65536"

/**
 * Algorithms that JVM MessageDigest or java.util.zip, or Apple CommonCrypto or zlib, also implement. Benchmarks are
 * parameterised by the algorithm names so the results for each implementation line up.
 */
internal val platformCoveredAlgorithms: Map<String, HashAlgorithm> = mapOf(
    "MD2" to Md.md2,
    "MD4" to Md.md4,
    "MD5" to Md.md5,
    "SHA-1" to Sha1.sha1,
    "SHA-224" to Sha2.sha224,
    "SHA-256" to Sha2.sha256,
    "SHA-384" to Sha2.sha384,
    "SHA-512" to Sha2.sha512,
    "SHA-512/224" to Sha2.sha512_224,
    "SHA-512/256" to Sha2.sha512_256,
    "SHA3-224" to Sha3.sha3_224,
    "SHA3-256" to Sha3.sha3_256,
    "SHA3-384" to Sha3.sha3_384,
    "SHA3-512" to Sha3.sha3_512,
    "Adler32" to Adler.adler32,
    "CRC32B" to Crc.crc32b,
    "CRC32C" to Crc.crc32c
)

internal val otherAlgorithms: Map<String, HashAlgorithm> = mapOf(
    "Blake2b-512" to Blake2.blake2b(512),
    "Blake2s-256" to Blake2.blake2s(256),
    "Blake3-256" to Blake3.blake3(),
    "XXH64" to XxHash.xxh64(),
    "XXH3-64" to XxHash.xxh3_64(),
    "MurmurHash3-x64-128" to MurmurHash.murmurHash3X64_128(),
    "CRC32" to Crc.crc32,
    // These rely on 64x64 -> 128-bit multiplies
    "XXH3-128" to XxHash.xxh3_128(),
    "rapidhash" to Rapidhash.rapidhash(),
    "komihash" to Komihash.komihash(),
    "wyhash-64" to Wyhash.wyhash64(),
    "t1ha1-le" to T1ha.t1ha1Le(),
    "t1ha2-atonce" to T1ha.t1ha2AtOnce(),
    "t1ha2-atonce128" to T1ha.t1ha2AtOnce128()
)

internal fun benchmarkInput(size: Int): ByteArray = ByteArray(size) { (it * 31 + 7).toByte() }

/**
 * Throws if a platform implementation disagrees with cryptohash, so the benchmarks always compare like with like
 */
internal fun requireMatchesCryptohash(algorithmName: String, input: ByteArray, platformOutput: ByteArray) {
    val expected = platformCoveredAlgorithms.getValue(algorithmName).hash(input)
    check(expected.contentEquals(platformOutput)) { "$algorithmName: platform output differs from cryptohash" }
}
