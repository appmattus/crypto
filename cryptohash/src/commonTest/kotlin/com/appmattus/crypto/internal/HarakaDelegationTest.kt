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
import com.appmattus.crypto.Haraka
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.Haraka256_256 and Haraka512_256 are implemented by cryptohash-haraka, whose own tests cover Haraka itself.
 * This checks that cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same.
 */
class HarakaDelegationTest {

    // Haraka hashes exactly 32 or 64 bytes
    private val input32 = ByteArray(32) { (it * 167 + 13).toByte() }
    private val input64 = ByteArray(64) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashHaraka() {
        testDigestKat({ CoreDigest.create(Algorithm.Haraka256_256) }, input32, Haraka.haraka256.hash(input32).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Haraka512_256) }, input64, Haraka.haraka512.hash(input64).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.Haraka256_256 to 32,
            Algorithm.Haraka512_256 to 32
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
