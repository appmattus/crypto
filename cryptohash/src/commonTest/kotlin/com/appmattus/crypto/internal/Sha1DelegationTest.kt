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
import com.appmattus.crypto.Sha1
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.SHA_*` entries for SHA-0 and SHA-1 hashes are backed by the cryptohash-sha1 module
 */
class Sha1DelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    @Suppress("DEPRECATION")
    fun createsDigestsBackedByCryptohashSha1() {
        testDigestKat({ CoreDigest.create(Algorithm.SHA_0) }, input, Sha1.sha0.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.SHA_1) }, input, Sha1.sha1.hash(input).toHexString())
    }

    @Test
    @Suppress("DEPRECATION")
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(Sha1.sha0.newHmac(key).digest(input), Algorithm.SHA_0.hmac(key, input))
        assertContentEquals(Sha1.sha0.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_0.hmac(key, input, outputLength = 10))
        assertContentEquals(Sha1.sha1.newHmac(key).digest(input), Algorithm.SHA_1.hmac(key, input))
        assertContentEquals(Sha1.sha1.newHmac(key, outputLength = 10).digest(input), Algorithm.SHA_1.hmac(key, input, outputLength = 10))
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.SHA_0 to 20,
            Algorithm.SHA_1 to 20
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
