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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.HighwayHash
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.HighwayHash*` entries are backed by the cryptohash-highwayhash module
 */
class HighwayHashDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = longArrayOf(0x0706050403020100L, 0x0F0E0D0C0B0A0908L, 0x1716151413121110L, 0x1F1E1D1C1B1A1918L)

    @Test
    @Suppress("DEPRECATION")
    fun createsDigestsBackedByCryptohashHighwayHash() {
        testDigestKat({ CoreDigest.create(Algorithm.HighwayHash64(key)) }, input, HighwayHash.highwayHash64(key).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HighwayHash128(key)) }, input, HighwayHash.highwayHash128(key).hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.HighwayHash256(key)) }, input, HighwayHash.highwayHash256(key).hash(input).toHexString())
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.HighwayHash64(key) to 8,
            Algorithm.HighwayHash128(key) to 16,
            Algorithm.HighwayHash256(key) to 32
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
