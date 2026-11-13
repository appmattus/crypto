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
import com.appmattus.crypto.BMW
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.BMW*` entries are backed by the cryptohash-bmw module
 */
class BMWDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashBMW() {
        testKat({ CoreDigest.create(Algorithm.BMW224) }, input, BMW.bmw224.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.BMW256) }, input, BMW.bmw256.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.BMW384) }, input, BMW.bmw384.hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.BMW512) }, input, BMW.bmw512.hash(input).toHexString())
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        assertContentEquals(BMW.bmw224.newHmac(key).digest(input), Algorithm.BMW224.hmac(key, input))
        assertContentEquals(BMW.bmw224.newHmac(key, outputLength = 10).digest(input), Algorithm.BMW224.hmac(key, input, outputLength = 10))
        assertContentEquals(BMW.bmw256.newHmac(key).digest(input), Algorithm.BMW256.hmac(key, input))
        assertContentEquals(BMW.bmw256.newHmac(key, outputLength = 10).digest(input), Algorithm.BMW256.hmac(key, input, outputLength = 10))
        assertContentEquals(BMW.bmw384.newHmac(key).digest(input), Algorithm.BMW384.hmac(key, input))
        assertContentEquals(BMW.bmw384.newHmac(key, outputLength = 10).digest(input), Algorithm.BMW384.hmac(key, input, outputLength = 10))
        assertContentEquals(BMW.bmw512.newHmac(key).digest(input), Algorithm.BMW512.hmac(key, input))
        assertContentEquals(BMW.bmw512.newHmac(key, outputLength = 10).digest(input), Algorithm.BMW512.hmac(key, input, outputLength = 10))
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.BMW224 to 28,
            Algorithm.BMW256 to 32,
            Algorithm.BMW384 to 48,
            Algorithm.BMW512 to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
