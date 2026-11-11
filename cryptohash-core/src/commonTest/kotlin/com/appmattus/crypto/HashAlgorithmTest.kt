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
import kotlin.test.assertFailsWith

class HashAlgorithmTest {

    // A "hash" whose output is exactly the bytes it was given, so each default can be checked against its input
    private class IdentityHasher : Hasher {
        private var buffer = ByteArray(0)

        override fun update(input: Byte): Hasher = apply { buffer += input }

        override fun update(input: ByteArray): Hasher = update(input, 0, input.size)

        override fun update(input: ByteArray, offset: Int, length: Int): Hasher =
            apply { buffer += input.copyOfRange(offset, offset + length) }

        override fun digest(): ByteArray = buffer.also { reset() }

        override fun digest(input: ByteArray): ByteArray = update(input).digest()

        override fun digest(output: ByteArray, offset: Int, length: Int): Int {
            val result = digest()
            result.copyInto(output, offset)
            return result.size
        }

        override val digestLength: Int
            get() = buffer.size

        override fun reset() {
            buffer = ByteArray(0)
        }

        override fun copy(): Hasher = IdentityHasher().also { it.buffer = buffer.copyOf() }

        override val blockLength: Int
            get() = 1

        override fun toString(): String = "identity"
    }

    private val algorithm = object : HashAlgorithm {
        override val blockLength: Int
            get() = 1

        override fun newHasher(): Hasher = IdentityHasher()
    }

    private val input = byteArrayOf(1, 2, 3, 4, 5)

    @Test
    fun hashesAWholeArray() {
        assertContentEquals(input, algorithm.hash(input))
    }

    @Test
    fun hashesARange() {
        assertContentEquals(byteArrayOf(2, 3, 4), algorithm.hash(input, 1, 3))
        assertContentEquals(byteArrayOf(), algorithm.hash(input, 5, 0))
    }

    @Test
    fun hashesTheUtf8EncodingOfAString() {
        assertContentEquals("héllo".encodeToByteArray(), algorithm.hash("héllo"))
    }

    @Test
    fun rejectsARangeOutsideTheInput() {
        assertFailsWith<IndexOutOfBoundsException> { algorithm.hash(input, -1, 2) }
        assertFailsWith<IndexOutOfBoundsException> { algorithm.hash(input, 0, -1) }
        assertFailsWith<IndexOutOfBoundsException> { algorithm.hash(input, 4, 2) }
        assertFailsWith<IndexOutOfBoundsException> { algorithm.hash(input, 6, 0) }
    }
}
