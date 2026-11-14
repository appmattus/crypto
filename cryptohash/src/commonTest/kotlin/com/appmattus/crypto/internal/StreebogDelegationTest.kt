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
import com.appmattus.crypto.Streebog
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Algorithm.GOST3411_2012_256 and GOST3411_2012_512 are implemented by cryptohash-streebog, whose own tests cover
 * Streebog itself. This checks that cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same, including HMAC.
 */
class StreebogDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashStreebog() {
        testDigestKat({ CoreDigest.create(Algorithm.GOST3411_2012_256) }, input, Streebog.streebog256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.GOST3411_2012_512) }, input, Streebog.streebog512.hash(input).toHexString())
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(Streebog.streebog256.newHmac(key).digest(input), Algorithm.GOST3411_2012_256.hmac(key, input))
        assertContentEquals(Streebog.streebog256.newHmac(key, outputLength = 10).digest(input), Algorithm.GOST3411_2012_256.hmac(key, input, outputLength = 10))
        assertContentEquals(Streebog.streebog512.newHmac(key).digest(input), Algorithm.GOST3411_2012_512.hmac(key, input))
        assertContentEquals(Streebog.streebog512.newHmac(key, outputLength = 10).digest(input), Algorithm.GOST3411_2012_512.hmac(key, input, outputLength = 10))
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.GOST3411_2012_256 to 32,
            Algorithm.GOST3411_2012_512 to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
