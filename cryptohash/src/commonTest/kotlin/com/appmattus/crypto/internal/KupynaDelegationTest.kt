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
import com.appmattus.crypto.Kupyna
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.Kupyna_256, Kupyna_384 and Kupyna_512 are implemented by cryptohash-kupyna, whose own tests cover Kupyna
 * itself. This checks that cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same.
 */
class KupynaDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashKupyna() {
        testDigestKat({ CoreDigest.create(Algorithm.Kupyna_256) }, input, Kupyna.kupyna256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Kupyna_384) }, input, Kupyna.kupyna384.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Kupyna_512) }, input, Kupyna.kupyna512.hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.Kupyna_256 to 32,
            Algorithm.Kupyna_384 to 48,
            Algorithm.Kupyna_512 to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
