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
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * The digests that buffer their input until [com.appmattus.crypto.Digest.digest] is called must hash the buffered
 * input and then reset, whichever digest function is called
 */
class NonIncrementalDigestTest {

    private val input = "The quick brown fox jumps over the lazy dog".encodeToByteArray()

    private val algorithms: List<Algorithm> = listOf(
        Algorithm.CityHash32,
        Algorithm.CityHash64(),
        Algorithm.CityHash128(),
        Algorithm.CityHashCrc128(),
        Algorithm.CityHashCrc256,
        Algorithm.FarmHash32(),
        Algorithm.FarmHash64(),
        Algorithm.FarmHash128(),
        Algorithm.MurmurHash1(),
        Algorithm.MurmurHash2(),
        Algorithm.MurmurHash64A(),
        Algorithm.MurmurHash64B(),
        Algorithm.Wyhash32(),
        Algorithm.T1ha0_32le(),
        Algorithm.T1ha1_le(),
        Algorithm.T1ha2_AtOnce(),
        Algorithm.T1ha2_AtOnce128(),
        Algorithm.Rapidhash(),
        Algorithm.RapidhashMicro(),
        Algorithm.RapidhashNano(),
        Algorithm.Komihash()
    )

    @Test
    fun updateThenDigestHashesTheBufferedInput() {
        for (algorithm in algorithms) {
            val digest = algorithm.createDigest()
            digest.update(input, 0, 10)
            digest.update(input, 10, input.size - 10)
            assertContentEquals(algorithm.hash(input), digest.digest(), "$algorithm")
        }
    }

    @Test
    fun digestResets() {
        for (algorithm in algorithms) {
            val digest = algorithm.createDigest()
            assertContentEquals(algorithm.hash(input), digest.digest(input), "$algorithm first digest")
            assertContentEquals(algorithm.hash(input), digest.digest(input), "$algorithm second digest")

            digest.update(input)
            digest.digest()
            assertContentEquals(algorithm.hash(ByteArray(0)), digest.digest(), "$algorithm digest after reset")
        }
    }

    @Test
    fun digestIntoOutputResets() {
        for (algorithm in algorithms) {
            val digest = algorithm.createDigest()
            val output = ByteArray(digest.digestLength)
            digest.update(input)
            digest.digest(output, 0, output.size)
            assertContentEquals(algorithm.hash(input), output, "$algorithm")
            assertContentEquals(algorithm.hash(input), digest.digest(input), "$algorithm after digest into output")
        }
    }

    @Test
    fun copyContinuesFromTheSameState() {
        for (algorithm in algorithms) {
            val digest = algorithm.createDigest()
            digest.update(input, 0, 10)
            val copy = digest.copy()
            copy.update(input, 10, input.size - 10)
            assertContentEquals(algorithm.hash(input), copy.digest(), "$algorithm")
        }
    }
}
