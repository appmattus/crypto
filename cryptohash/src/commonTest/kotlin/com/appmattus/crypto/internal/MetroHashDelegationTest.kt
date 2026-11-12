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
import com.appmattus.crypto.MetroHash
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Algorithm.MetroHash64 and Algorithm.MetroHash128 are implemented by cryptohash-metrohash, whose own tests cover
 * MetroHash itself. This checks that cryptohash's [com.appmattus.crypto.Digest] view of them behaves the same.
 */
class MetroHashDelegationTest {

    private val input = ByteArray(200) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashMetroHash() {
        testKat({ CoreDigest.create(Algorithm.MetroHash64()) }, "hello world", "22d16db35723c197")
        testKat({ CoreDigest.create(Algorithm.MetroHash64(5u)) }, input, MetroHash.metroHash64(5u).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.MetroHash128(0u)) }, "hello world", "a65997de23891a0edccc401bbe2ef561")
        testKat({ CoreDigest.create(Algorithm.MetroHash128(5u)) }, input, MetroHash.metroHash128(5u).hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(Algorithm.MetroHash64() to 8, Algorithm.MetroHash128() to 16).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
