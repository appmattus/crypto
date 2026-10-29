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

import com.appmattus.crypto.Algorithm

/**
 * Input sizes in bytes for every benchmark: a short key, a small message and a large message
 */
internal const val SIZE_SMALL = "64"
internal const val SIZE_MEDIUM = "1024"
internal const val SIZE_LARGE = "65536"

/**
 * Algorithms that JVM MessageDigest or java.util.zip, or Apple CommonCrypto or zlib, also implement. Benchmarks are
 * parameterised by [Algorithm.algorithmName] so the results for each implementation line up.
 */
internal val platformCoveredAlgorithms: Map<String, Algorithm> = listOf(
    Algorithm.MD2,
    Algorithm.MD4,
    Algorithm.MD5,
    Algorithm.SHA_1,
    Algorithm.SHA_224,
    Algorithm.SHA_256,
    Algorithm.SHA_384,
    Algorithm.SHA_512,
    Algorithm.SHA_512_224,
    Algorithm.SHA_512_256,
    Algorithm.SHA3_224,
    Algorithm.SHA3_256,
    Algorithm.SHA3_384,
    Algorithm.SHA3_512,
    Algorithm.Adler32,
    Algorithm.CRC32B,
    Algorithm.CRC32C
).associateBy { it.algorithmName }

/**
 * Popular algorithms with no platform implementation, for comparison
 */
internal val otherAlgorithms: Map<String, Algorithm> = listOf(
    Algorithm.Blake2b_512,
    Algorithm.Blake2s_256,
    Algorithm.Blake3(),
    Algorithm.XXHash64(),
    Algorithm.XXH3_64(),
    Algorithm.MurmurHash3_X64_128(),
    Algorithm.CRC32,
    // These rely on 64x64 -> 128-bit multiplies
    Algorithm.XXH3_128(),
    Algorithm.Rapidhash(),
    Algorithm.Komihash(),
    Algorithm.Wyhash(),
    Algorithm.T1ha1_le(),
    Algorithm.T1ha2_AtOnce(),
    Algorithm.T1ha2_AtOnce128()
).associateBy { it.algorithmName }

/**
 * The same deterministic input for every benchmark
 */
internal fun benchmarkInput(size: Int): ByteArray = ByteArray(size) { (it * 31 + 7).toByte() }

/**
 * Throws if a platform implementation disagrees with cryptohash, so the benchmarks always compare like with like
 */
internal fun requireMatchesCryptohash(algorithmName: String, input: ByteArray, platformOutput: ByteArray) {
    val expected = platformCoveredAlgorithms.getValue(algorithmName).hash(input)
    check(expected.contentEquals(platformOutput)) { "$algorithmName: platform output differs from cryptohash" }
}
