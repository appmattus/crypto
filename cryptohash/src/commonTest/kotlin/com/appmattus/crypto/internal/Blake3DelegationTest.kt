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
import com.appmattus.crypto.Blake3
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Checks `Algorithm.Blake3` and its keyed and key derivation modes are backed by the cryptohash-blake3 module
 */
class Blake3DelegationTest {

    private val input = ByteArray(3000) { (it * 167 + 13).toByte() }

    private val key = ByteArray(32) { (it * 31 + 7).toByte() }

    private val context = "cryptohash delegation test".encodeToByteArray()

    @Test
    @Suppress("DEPRECATION")
    fun createsDigestsBackedByCryptohashBlake3() {
        listOf(
            Algorithm.Blake3() to Blake3.blake3(),
            Algorithm.Blake3(100) to Blake3.blake3(100),
            Algorithm.Blake3.Keyed(key) to Blake3.blake3Keyed(key),
            Algorithm.Blake3.Keyed(key, 50) to Blake3.blake3Keyed(key, 50),
            Algorithm.Blake3.DeriveKey(context) to Blake3.blake3DeriveKey(context),
            Algorithm.Blake3.DeriveKey(context, 70) to Blake3.blake3DeriveKey(context, 70)
        ).forEach { (algorithm, module) ->
            testDigestKat({ CoreDigest.create(algorithm) }, input, module.hash(input).toHexString())
        }
    }

    @Test
    @Suppress("DEPRECATION")
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.Blake3() to 32,
            Algorithm.Blake3(100) to 100,
            Algorithm.Blake3.Keyed(key, 50) to 50,
            Algorithm.Blake3.DeriveKey(context, 70) to 70
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
