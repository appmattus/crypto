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
import com.appmattus.crypto.CubeHash
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.CubeHash*` entries are backed by the cryptohash-cubehash module
 */
class CubeHashDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashCubeHash() {
        testDigestKat({ CoreDigest.create(Algorithm.CubeHash224) }, input, CubeHash.cubeHash224.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.CubeHash256) }, input, CubeHash.cubeHash256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.CubeHash384) }, input, CubeHash.cubeHash384.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.CubeHash512) }, input, CubeHash.cubeHash512.hash(input).toHexString())
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.CubeHash224 to 28,
            Algorithm.CubeHash256 to 32,
            Algorithm.CubeHash384 to 48,
            Algorithm.CubeHash512 to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
