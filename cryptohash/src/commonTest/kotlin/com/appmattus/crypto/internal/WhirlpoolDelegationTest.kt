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
import com.appmattus.crypto.Whirlpool
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * The Whirlpool algorithms are implemented by cryptohash-whirlpool, whose own tests cover them. This checks that
 * cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same, including HMAC.
 */
class WhirlpoolDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashWhirlpool() {
        testDigestKat({ CoreDigest.create(Algorithm.Whirlpool) }, input, Whirlpool.whirlpool.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Whirlpool0) }, input, Whirlpool.whirlpool0.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.WhirlpoolT) }, input, Whirlpool.whirlpoolT.hash(input).toHexString())
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(Whirlpool.whirlpool.newHmac(key).digest(input), Algorithm.Whirlpool.hmac(key, input))
        assertContentEquals(Whirlpool.whirlpool.newHmac(key, outputLength = 10).digest(input), Algorithm.Whirlpool.hmac(key, input, outputLength = 10))
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.Whirlpool to 64,
            Algorithm.Whirlpool0 to 64,
            Algorithm.WhirlpoolT to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
