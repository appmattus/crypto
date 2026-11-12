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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Hasher
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AbstractHasherTest {

    /** Records every byte it is given, and digests to them all */
    private class RecordingHasher : AbstractHasher() {
        private val bytes = mutableListOf<Byte>()

        override fun update(input: ByteArray, offset: Int, length: Int): Hasher = apply {
            for (i in offset until offset + length) bytes += input[i]
        }

        override fun digest(): ByteArray = bytes.toByteArray().also { reset() }

        override val digestLength: Int
            get() = bytes.size

        override fun reset() = bytes.clear()

        override fun copy(): Hasher = RecordingHasher().also { it.bytes += bytes }

        override fun toString(): String = "Recording"
    }

    @Test
    fun overloadsForwardToTheRangeUpdate() {
        val hasher = RecordingHasher()
        hasher.update(1).update(byteArrayOf(2, 3))
        assertContentEquals(byteArrayOf(1, 2, 3, 4), hasher.digest(byteArrayOf(4)))
    }

    @Test
    fun digestsIntoTheOutputAtTheOffset() {
        val hasher = RecordingHasher().update(byteArrayOf(5, 6))
        val output = ByteArray(4)
        assertEquals(2, hasher.digest(output, 1, 2))
        assertContentEquals(byteArrayOf(0, 5, 6, 0), output)
    }

    @Test
    fun rejectsTooSmallAnOutput() {
        assertFailsWith<IllegalArgumentException> { RecordingHasher().update(byteArrayOf(5, 6)).digest(ByteArray(4), 0, 1) }
        assertFailsWith<IllegalArgumentException> { RecordingHasher().update(byteArrayOf(5, 6)).digest(ByteArray(4), 3, 2) }
    }
}
