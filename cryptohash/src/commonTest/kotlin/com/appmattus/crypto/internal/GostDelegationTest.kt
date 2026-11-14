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
import com.appmattus.crypto.Gost
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Algorithm.GOST3411_94 is implemented by cryptohash-gost, whose own tests cover GOST R 34.11-94 itself. This checks
 * that cryptohash's [com.appmattus.crypto.Digest] view of it behaves the same, including HMAC.
 */
class GostDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    @Suppress("DEPRECATION")
    fun createsDigestsBackedByCryptohashGost() {
        testDigestKat({ CoreDigest.create(Algorithm.GOST3411_94) }, input, Gost.gost3411_94.hash(input).toHexString())
    }

    @Test
    @Suppress("DEPRECATION")
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(Gost.gost3411_94.newHmac(key).digest(input), Algorithm.GOST3411_94.hmac(key, input))
        assertContentEquals(Gost.gost3411_94.newHmac(key, outputLength = 10).digest(input), Algorithm.GOST3411_94.hmac(key, input, outputLength = 10))
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.GOST3411_94 to 32
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
