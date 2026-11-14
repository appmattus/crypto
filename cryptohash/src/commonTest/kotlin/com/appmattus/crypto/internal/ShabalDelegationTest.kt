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
import com.appmattus.crypto.Shabal
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.Shabal*` entries are backed by the cryptohash-shabal module
 */
class ShabalDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashShabal() {
        testDigestKat({ CoreDigest.create(Algorithm.Shabal192) }, input, Shabal.shabal192.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Shabal224) }, input, Shabal.shabal224.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Shabal256) }, input, Shabal.shabal256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Shabal384) }, input, Shabal.shabal384.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.Shabal512) }, input, Shabal.shabal512.hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.Shabal192 to 24,
            Algorithm.Shabal224 to 28,
            Algorithm.Shabal256 to 32,
            Algorithm.Shabal384 to 48,
            Algorithm.Shabal512 to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
