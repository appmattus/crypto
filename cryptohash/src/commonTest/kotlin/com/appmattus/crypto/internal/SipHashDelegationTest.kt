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
import com.appmattus.crypto.SipHash
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks `Algorithm.SipHash` and `Algorithm.SipHash128` are backed by the cryptohash-siphash module
 */
class SipHashDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(16) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashSipHash() {
        testKat({ CoreDigest.create(Algorithm.SipHash(key)) }, input, SipHash.sipHash(key).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SipHash(key, 1, 3)) }, input, SipHash.sipHash(key, 1, 3).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SipHash128(key)) }, input, SipHash.sipHash128(key).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.SipHash128(key, 4, 8)) }, input, SipHash.sipHash128(key, 4, 8).hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.SipHash(key) to 8,
            Algorithm.SipHash(key, 1, 3) to 8,
            Algorithm.SipHash128(key) to 16,
            Algorithm.SipHash128(key, 4, 8) to 16
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }

    @Test
    fun algorithmToStringShowsRoundsButNotKey() {
        assertEquals("SipHash-2-4(key=ByteArray(size=16))", Algorithm.SipHash(key).toString())
    }
}
