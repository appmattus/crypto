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
import com.appmattus.crypto.T1ha
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.T1ha*` entries are backed by the cryptohash-t1ha module
 */
class T1haDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashT1ha() {
        testKat({ CoreDigest.create(Algorithm.T1ha0_32le(5u)) }, input, T1ha.t1ha0_32le(5u).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.T1ha1_le(5u)) }, input, T1ha.t1ha1_le(5u).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.T1ha2_AtOnce(5u)) }, input, T1ha.t1ha2AtOnce(5u).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.T1ha2_AtOnce128(5u)) }, input, T1ha.t1ha2AtOnce128(5u).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.T1ha2_Stream(5u, 7u)) }, input, T1ha.t1ha2Stream(5u, 7u).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.T1ha2_Stream128(5u, 7u)) }, input, T1ha.t1ha2Stream128(5u, 7u).hash(input).toHexString())
    }

    @Test
    fun streamSeedYDefaultsToSeedX() {
        testKat({ CoreDigest.create(Algorithm.T1ha2_Stream(5u)) }, input, T1ha.t1ha2Stream(5u, 5u).hash(input).toHexString())
        testKat({ CoreDigest.create(Algorithm.T1ha2_Stream128(5u)) }, input, T1ha.t1ha2Stream128(5u, 5u).hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.T1ha0_32le() to 8,
            Algorithm.T1ha1_le() to 8,
            Algorithm.T1ha2_AtOnce() to 8,
            Algorithm.T1ha2_AtOnce128() to 16,
            Algorithm.T1ha2_Stream() to 8,
            Algorithm.T1ha2_Stream128() to 16
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
