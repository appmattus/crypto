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
import com.appmattus.crypto.Skein
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks the `Algorithm.Skein*` entries are backed by the cryptohash-skein module
 */
class SkeinDelegationTest {

    private val input = ByteArray(300) { (it * 167 + 13).toByte() }

    private val key = ByteArray(100) { (it * 31 + 7).toByte() }

    @Test
    fun createsDigestsBackedByCryptohashSkein() {
        listOf(
            Algorithm.Skein256_128 to Skein.skein256_128,
            Algorithm.Skein256_160 to Skein.skein256_160,
            Algorithm.Skein256_224 to Skein.skein256_224,
            Algorithm.Skein256_256 to Skein.skein256_256,
            Algorithm.Skein512_128 to Skein.skein512_128,
            Algorithm.Skein512_160 to Skein.skein512_160,
            Algorithm.Skein512_224 to Skein.skein512_224,
            Algorithm.Skein512_256 to Skein.skein512_256,
            Algorithm.Skein512_384 to Skein.skein512_384,
            Algorithm.Skein512_512 to Skein.skein512_512,
            Algorithm.Skein1024_384 to Skein.skein1024_384,
            Algorithm.Skein1024_512 to Skein.skein1024_512,
            Algorithm.Skein1024_1024 to Skein.skein1024_1024,
            Algorithm.Skein(256, 1024) to Skein.skein(256, 1024),
            Algorithm.Skein.Keyed(512, 384, key) to Skein.skeinKeyed(512, 384, key),
            Algorithm.Skein.Keyed(1024, 160, ByteArray(0)) to Skein.skeinKeyed(1024, 160, ByteArray(0))
        ).forEach { (algorithm, module) ->
            testDigestKat({ CoreDigest.create(algorithm) }, input, module.hash(input).toHexString())
        }
    }

    @Test
    fun createsHmacsMatchingTheModule() {
        listOf(
            Algorithm.Skein256_160 to Skein.skein256_160,
            Algorithm.Skein512_512 to Skein.skein512_512,
            Algorithm.Skein1024_1024 to Skein.skein1024_1024
        ).forEach { (algorithm, module) ->
            assertContentEquals(module.newHmac(key).digest(input), algorithm.hmac(key, input))
            assertContentEquals(module.newHmac(key, outputLength = 10).digest(input), algorithm.hmac(key, input, outputLength = 10))
        }
    }

    @Test
    fun describesItselfAsTheAlgorithm() {
        listOf(
            Algorithm.Skein256_128 to 16,
            Algorithm.Skein256_160 to 20,
            Algorithm.Skein256_224 to 28,
            Algorithm.Skein256_256 to 32,
            Algorithm.Skein512_128 to 16,
            Algorithm.Skein512_160 to 20,
            Algorithm.Skein512_224 to 28,
            Algorithm.Skein512_256 to 32,
            Algorithm.Skein512_384 to 48,
            Algorithm.Skein512_512 to 64,
            Algorithm.Skein1024_384 to 48,
            Algorithm.Skein1024_512 to 64,
            Algorithm.Skein1024_1024 to 128,
            Algorithm.Skein(256, 1024) to 128,
            Algorithm.Skein.Keyed(512, 384, key) to 48
        ).forEach { (algorithm, digestLength) ->
            val digest = algorithm.createDigest()
            assertEquals(algorithm.blockLength, digest.blockLength)
            assertEquals(digestLength, digest.digestLength)
            assertEquals(algorithm.algorithmName, digest.toString())
            assertEquals(algorithm.algorithmName, digest.copy().toString())
        }
    }
}
