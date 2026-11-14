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
import com.appmattus.crypto.Sm3
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks `Algorithm.SM3` is backed by the cryptohash-sm3 module
 */
class Sm3DelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashSm3() {
        testDigestKat({ CoreDigest.create(Algorithm.SM3) }, input, Sm3.sm3.hash(input).toHexString())
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(Sm3.sm3.newHmac(key).digest(input), Algorithm.SM3.hmac(key, input))
        assertContentEquals(Sm3.sm3.newHmac(key, outputLength = 10).digest(input), Algorithm.SM3.hmac(key, input, outputLength = 10))
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.SM3 to 32
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
