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
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Checks the slicing-by-8 path of `update(ByteArray, Int, Int)` against the byte-at-a-time `update(Byte)` path,
 * for every input length up to a few blocks and at unaligned offsets.
 */
class CRC32SlicingTest {

    private val data = Random(0).nextBytes(MAX_LENGTH + MAX_OFFSET)

    @Test
    fun crc32() = check(Algorithm.CRC32)

    @Test
    fun crc32b() = check(Algorithm.CRC32B)

    @Test
    fun crc32c() = check(Algorithm.CRC32C)

    private fun check(algorithm: Algorithm) {
        for (offset in 0..MAX_OFFSET) {
            for (length in 0..MAX_LENGTH) {
                check(algorithm, offset, length)
            }
        }
    }

    private fun check(algorithm: Algorithm, offset: Int, length: Int) {
        val expected = CoreDigest.create(algorithm).run {
            for (i in offset until offset + length) update(data[i])
            digest()
        }

        val bulk = CoreDigest.create(algorithm).run {
            update(data, offset, length)
            digest()
        }
        assertContentEquals(expected, bulk, "$algorithm offset=$offset length=$length")

        // Split into two updates so the second starts mid-block with a non-zero register
        val split = length / 3
        val chunked = CoreDigest.create(algorithm).run {
            update(data, offset, split)
            update(data, offset + split, length - split)
            digest()
        }
        assertContentEquals(expected, chunked, "$algorithm offset=$offset length=$length split=$split")
    }

    private companion object {
        const val MAX_LENGTH = 100
        const val MAX_OFFSET = 7
    }
}
