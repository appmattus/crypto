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
import com.appmattus.crypto.Blake2
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.Blake2*` entries are backed by the cryptohash-blake2 module
 */
class Blake2DelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(20) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashBlake2() {
        listOf(
            Algorithm.Blake2b_160 to Blake2.blake2b(160),
            Algorithm.Blake2b_256 to Blake2.blake2b(256),
            Algorithm.Blake2b_384 to Blake2.blake2b(384),
            Algorithm.Blake2b_512 to Blake2.blake2b(512),
            Algorithm.Blake2b(200) to Blake2.blake2b(200),
            Algorithm.Blake2b.Keyed(key, ByteArray(16) { 1 }, ByteArray(16) { 2 }, 320) to
                Blake2.blake2bKeyed(key, ByteArray(16) { 1 }, ByteArray(16) { 2 }, 320),
            Algorithm.Blake2s_128 to Blake2.blake2s(128),
            Algorithm.Blake2s_160 to Blake2.blake2s(160),
            Algorithm.Blake2s_224 to Blake2.blake2s(224),
            Algorithm.Blake2s_256 to Blake2.blake2s(256),
            Algorithm.Blake2s(96) to Blake2.blake2s(96),
            Algorithm.Blake2s.Keyed(key, ByteArray(8) { 1 }, ByteArray(8) { 2 }, 200) to
                Blake2.blake2sKeyed(key, ByteArray(8) { 1 }, ByteArray(8) { 2 }, 200)
        ).forEach { (algorithm, module) ->
            testKat({ CoreDigest.create(algorithm) }, input, module.hash(input).toHexString())
        }
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.Blake2b_160 to 20,
            Algorithm.Blake2b_512 to 64,
            Algorithm.Blake2b(200) to 25,
            Algorithm.Blake2b.Keyed(key, outputSizeBits = 320) to 40,
            Algorithm.Blake2s_128 to 16,
            Algorithm.Blake2s_256 to 32,
            Algorithm.Blake2s(96) to 12,
            Algorithm.Blake2s.Keyed(key, outputSizeBits = 200) to 25
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
