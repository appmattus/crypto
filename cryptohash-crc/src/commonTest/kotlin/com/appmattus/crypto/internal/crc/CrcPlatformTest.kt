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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.CRC
import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Checks [CRC.crc32b] and [CRC.crc32c], which use the platform's own implementation where there is one, against the
 * pure Kotlin hashers. Where the platform has none, both sides are the pure Kotlin hasher.
 */
class CrcPlatformTest {

    private val data = Random(0).nextBytes(LARGE)

    private val algorithms: List<Pair<HashAlgorithm, () -> Hasher>> = listOf(
        CRC.crc32b to ::Crc32bHasher,
        CRC.crc32c to ::Crc32cHasher
    )

    @Test
    fun properties() = algorithms.forEach { (algorithm, pure) ->
        val hasher = algorithm.newHasher()
        assertEquals(pure().digestLength, hasher.digestLength, "$algorithm digestLength")
        assertEquals(pure().toString(), hasher.toString(), "$algorithm toString")
    }

    @Test
    fun singleAndSplitUpdates() = algorithms.forEach { (algorithm, pure) ->
        // Every length up to a few blocks, either side of the JVM's java.util.zip threshold, and some longer ones
        for (length in (0..SHORT) + listOf(1000, 4095, 4096, 4097, 65_536)) {
            val expected = pure().update(data, OFFSET, length).digest()
            assertContentEquals(expected, algorithm.newHasher().update(data, OFFSET, length).digest(), "$algorithm length=$length")

            val split = length / 3
            val actual = algorithm.newHasher().update(data, OFFSET, split).update(data, OFFSET + split, length - split).digest()
            assertContentEquals(expected, actual, "$algorithm split length=$length")
        }
    }

    @Test
    fun byteUpdatesAndLargeInput() = algorithms.forEach { (algorithm, pure) ->
        val expected = pure().update(data, 0, SHORT).digest()
        val hasher = algorithm.newHasher()
        for (i in 0 until SHORT) hasher.update(data[i])
        assertContentEquals(expected, hasher.digest(), "$algorithm bytes")

        assertContentEquals(pure().digest(data), algorithm.newHasher().digest(data), "$algorithm large")
    }

    @Test
    fun copyMidStreamAndReuse() = algorithms.forEach { (algorithm, pure) ->
        val hasher = algorithm.newHasher().update(data, 0, 100)
        val copy = hasher.copy()
        hasher.update(data, 100, 200)
        copy.update(data, 100, 50)
        assertContentEquals(pure().update(data, 0, 300).digest(), hasher.digest(), "$algorithm original")
        assertContentEquals(pure().update(data, 0, 150).digest(), copy.digest(), "$algorithm copy")

        hasher.update(data, 0, 100).reset()
        assertContentEquals(pure().update(data, 0, 70).digest(), hasher.update(data, 0, 70).digest(), "$algorithm after reset")
    }

    private companion object {
        const val OFFSET = 5
        const val SHORT = 300
        const val LARGE = 100_000
    }
}
