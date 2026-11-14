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

import com.appmattus.crypto.Hasher
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Checks the slicing-by-8 path of `update(ByteArray, Int, Int)` against the byte-at-a-time `update(Byte)` path,
 * for every input length up to a few blocks and at unaligned offsets.
 */
class Crc32SlicingTest {

    private val data = Random(0).nextBytes(MAX_LENGTH + MAX_OFFSET)

    @Test
    fun crc32() = check("CRC32", ::Crc32Hasher)

    @Test
    fun crc32b() = check("CRC32B", ::Crc32bHasher)

    @Test
    fun crc32c() = check("CRC32C", ::Crc32cHasher)

    private fun check(algorithm: String, hasher: () -> Hasher) {
        for (offset in 0..MAX_OFFSET) {
            for (length in 0..MAX_LENGTH) {
                check(algorithm, hasher, offset, length)
            }
        }
    }

    private fun check(algorithm: String, hasher: () -> Hasher, offset: Int, length: Int) {
        val expected = hasher().run {
            for (i in offset until offset + length) update(data[i])
            digest()
        }

        val bulk = hasher().run {
            update(data, offset, length)
            digest()
        }
        assertContentEquals(expected, bulk, "$algorithm offset=$offset length=$length")

        // Split into two updates so the second starts mid-block with a non-zero register
        val split = length / 3
        val chunked = hasher().run {
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
