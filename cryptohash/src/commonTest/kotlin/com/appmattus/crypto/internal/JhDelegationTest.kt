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
import com.appmattus.crypto.Jh
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.JH*` entries are backed by the cryptohash-jh module
 */
class JhDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    @Test
    @Suppress("DEPRECATION")
    fun createsDigestsBackedByCryptohashJh() {
        testDigestKat({ CoreDigest.create(Algorithm.JH224) }, input, Jh.jh224.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.JH256) }, input, Jh.jh256.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.JH384) }, input, Jh.jh384.hash(input).toHexString())
        testDigestKat({ CoreDigest.create(Algorithm.JH512) }, input, Jh.jh512.hash(input).toHexString())
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.JH224 to 28,
            Algorithm.JH256 to 32,
            Algorithm.JH384 to 48,
            Algorithm.JH512 to 64
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
