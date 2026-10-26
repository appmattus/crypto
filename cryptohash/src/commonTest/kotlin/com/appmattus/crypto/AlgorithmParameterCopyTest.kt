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

package com.appmattus.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Algorithms must take a copy of array and list parameters, such as keys and secrets, so that changing the caller's
 * array after constructing the algorithm does not change the hashes it produces.
 */
class AlgorithmParameterCopyTest {

    private val input = "hello world".encodeToByteArray()

    @Test
    fun blake2sKeyedCopiesParameters() {
        val key = ByteArray(32) { 1 }
        val salt = ByteArray(8) { 2 }
        val personalisation = ByteArray(8) { 3 }
        assertUnaffectedByMutation(Algorithm.Blake2s.Keyed(key, salt, personalisation)) {
            key.fill(0)
            salt.fill(0)
            personalisation.fill(0)
        }
    }

    @Test
    fun blake2bKeyedCopiesParameters() {
        val key = ByteArray(64) { 1 }
        val salt = ByteArray(16) { 2 }
        val personalisation = ByteArray(16) { 3 }
        assertUnaffectedByMutation(Algorithm.Blake2b.Keyed(key, salt, personalisation)) {
            key.fill(0)
            salt.fill(0)
            personalisation.fill(0)
        }
    }

    @Test
    fun blake3KeyedCopiesKey() {
        val key = ByteArray(32) { 1 }
        assertUnaffectedByMutation(Algorithm.Blake3.Keyed(key)) { key.fill(0) }
    }

    @Test
    fun blake3DeriveKeyCopiesContext() {
        val context = "context".encodeToByteArray()
        assertUnaffectedByMutation(Algorithm.Blake3.DeriveKey(context)) { context.fill(0) }
    }

    @Test
    fun cShakeCopiesParameters() {
        val customisation = "custom".encodeToByteArray()
        val functionName = "function".encodeToByteArray()
        assertUnaffectedByMutation(Algorithm.cSHAKE128(customisation, functionName)) {
            customisation.fill(0)
            functionName.fill(0)
        }
        assertUnaffectedByMutation(Algorithm.cSHAKE256(customisation, functionName)) {
            customisation.fill(1)
            functionName.fill(1)
        }
    }

    @Test
    fun highwayHashCopiesKey() {
        val key = longArrayOf(1, 2, 3, 4)
        assertUnaffectedByMutation(Algorithm.HighwayHash64(key)) { key.fill(0) }
        assertUnaffectedByMutation(Algorithm.HighwayHash128(key)) { key.fill(5) }
        assertUnaffectedByMutation(Algorithm.HighwayHash256(key)) { key.fill(6) }
    }

    @Test
    fun skeinKeyedCopiesKey() {
        val key = ByteArray(32) { 1 }
        assertUnaffectedByMutation(Algorithm.Skein.Keyed(512, 512, key)) { key.fill(0) }
    }

    @Test
    fun wyhashCopiesSecret() {
        val secret = Algorithm.Wyhash.makeSecret(1u).toMutableList()
        assertUnaffectedByMutation(Algorithm.Wyhash(secret = secret)) { secret[0] = 0u }
    }

    @Test
    fun xxh3SecretCopiesSecret() {
        val secret = ByteArray(136) { it.toByte() }
        assertUnaffectedByMutation(Algorithm.XXH3_64.Secret(secret)) { secret.fill(0) }
        assertUnaffectedByMutation(Algorithm.XXH3_128.Secret(secret)) { secret.fill(1) }
    }

    private fun assertUnaffectedByMutation(algorithm: Algorithm, mutate: () -> Unit) {
        val expected = algorithm.hash(input)
        mutate()
        assertContentEquals(expected, algorithm.hash(input), "$algorithm changed after mutating its parameters")
    }
}
