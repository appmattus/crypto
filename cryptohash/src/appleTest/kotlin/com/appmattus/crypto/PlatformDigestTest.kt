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

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.convert
import platform.Foundation.NSMutableData
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@OptIn(ExperimentalForeignApi::class)
class PlatformDigestTest {

    private val input = "hello world".encodeToByteArray()
    private val expected = Algorithm.SHA_256.hash(input)

    private fun mutableData(size: Int) = NSMutableData().apply { setLength(size.convert()) }

    @Test
    fun digestWritesIntoMutableDataAtOffset() {
        val digest = Algorithm.SHA_256.createDigest().platform()
        val output = mutableData(40)

        digest.update(input.toData())
        val written = digest.digest(output, 4, 32)

        assertEquals(32, written)
        assertContentEquals(ByteArray(4) + expected + ByteArray(4), output.toByteArray())
    }

    @Test
    fun digestWritesTruncatedOutputWhenLengthIsShorterThanDigest() {
        val digest = Algorithm.SHA_256.createDigest().platform()
        val output = mutableData(16)

        digest.update(input.toData())
        val written = digest.digest(output, 0, 16)

        assertEquals(16, written)
        assertContentEquals(expected.copyOf(16), output.toByteArray())
    }

    @Test
    fun digestRejectsImmutableData() {
        val digest = Algorithm.SHA_256.createDigest().platform()

        assertFailsWith<IllegalArgumentException> {
            digest.digest(ByteArray(32).toData(), 0, 32)
        }
    }

    @Test
    fun digestRejectsOutputTooSmallWithoutResettingDigest() {
        val digest = Algorithm.SHA_256.createDigest().platform()
        digest.update(input.toData())

        assertFailsWith<IllegalArgumentException> {
            digest.digest(mutableData(31), 0, 32)
        }

        assertContentEquals(expected, digest.digest().toByteArray())
    }
}
