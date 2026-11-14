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

@file:Suppress("DEPRECATION")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Crc
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.CRC32, CRC32B and CRC32C are implemented by cryptohash-crc, whose own tests cover the CRCs themselves,
 * including its use of the platform's own implementations. This checks that cryptohash's
 * [com.appmattus.crypto.Digest] view of them behaves the same, through both [Algorithm.createDigest] and
 * [CoreDigest].
 */
class CrcDelegationTest {

    private val input = ByteArray(10_000) { (it * 167 + 13).toByte() }

    private val algorithms = listOf(
        Triple(Algorithm.CRC32, Crc.crc32, "73bb8c64"),
        Triple(Algorithm.CRC32B, Crc.crc32b, "352441c2"),
        Triple(Algorithm.CRC32C, Crc.crc32c, "364b3fb7")
    )

    @Test
    fun createsDigestsBackedByCryptohashCrc() = algorithms.forEach { (algorithm, crc, abc) ->
        testDigestKat({ algorithm.createDigest() }, "abc", abc)
        testDigestKat({ CoreDigest.create(algorithm) }, "abc", abc)
        testDigestKat({ algorithm.createDigest() }, input, crc.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(algorithm) }, input, crc.hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() = algorithms.forEach { (algorithm, _, _) ->
        val digest = algorithm.createDigest()
        assertEquals(algorithm.blockLength, digest.blockLength)
        assertEquals(4, digest.digestLength)
        assertEquals(algorithm.algorithmName, digest.toString())
        assertEquals(algorithm.algorithmName, digest.copy().toString())
    }
}
