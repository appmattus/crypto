/*
 * Copyright 2022 Appmattus Limited
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

package com.appmattus.crypto.internal.bytes

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ByteArrayArrayTest {

    @Test
    fun noContent() {
        val baa = ByteArrayArray()

        val exception = assertFailsWith<IndexOutOfBoundsException> {
            baa[0]
        }

        assertEquals("Index 0 out of bounds for length 0", exception.message)
    }

    @Test
    fun noContent2() {
        val baa = ByteArrayArray()

        val exception = assertFailsWith<IndexOutOfBoundsException> {
            baa[1]
        }

        assertEquals("Index 1 out of bounds for length 0", exception.message)
    }

    @Test
    fun x() {
        val baa = ByteArrayArray().apply {
            add(byteArrayOf(2, 3, 4))
            add(byteArrayOf(5, 6))
            add(byteArrayOf(7))
        }

        assertEquals(2, baa[0])
        assertEquals(3, baa[1])
        assertEquals(4, baa[2])
        assertEquals(5, baa[3])
        assertEquals(6, baa[4])
        assertEquals(7, baa[5])
    }

    @Test
    fun x2() {
        val baa = ByteArrayArray().apply {
            add(byteArrayOf(2, 3, 4), 1, 2)
            add(byteArrayOf(5, 6), 0, 1)
            add(byteArrayOf(7))
        }

        assertEquals(3, baa[0])
        assertEquals(4, baa[1])
        assertEquals(5, baa[2])
        assertEquals(7, baa[3])
    }

    @Test
    fun outOfBounds() {
        val baa = ByteArrayArray().apply {
            add(byteArrayOf(2, 3, 4))
            add(byteArrayOf(5, 6))
            add(byteArrayOf(7))
        }

        val exception = assertFailsWith<IndexOutOfBoundsException> {
            baa[6]
        }

        assertEquals("Index 6 out of bounds for length 6", exception.message)
    }

    @Test
    fun iterator() {
        val baa = ByteArrayArray().apply {
            add(byteArrayOf(2, 3, 4), 1, 2)
            add(byteArrayOf(5, 6), 0, 1)
            add(byteArrayOf(7))
        }

        assertContentEquals(listOf(3, 4, 5, 7), baa.iterator().asSequence().toList())
    }

    @Test
    fun copyIntoAll() {
        val baa = ByteArrayArray().apply {
            add(byteArrayOf(2, 3, 4))
            add(byteArrayOf(5, 6))
            add(byteArrayOf(7))
        }

        val bytes = ByteArray(6)

        // copy all bytes
        baa.copyInto(bytes)

        assertContentEquals(listOf(2, 3, 4, 5, 6, 7), bytes.toList())
    }

    @Test
    fun copyIntoPartial() {
        val baa = ByteArrayArray().apply {
            add(byteArrayOf(2, 3, 4))
            add(byteArrayOf(5, 6, 7))
        }

        val bytes = ByteArray(4)

        // copy partial bytes
        baa.copyInto(
            destination = bytes,
            destinationOffset = 0,
            startIndex = 1,
            endIndex = 5
        )

        assertContentEquals(listOf(3, 4, 5, 6), bytes.toList())
    }

    @Test
    fun copyIntoPartialWithOffset() {
        val baa = ByteArrayArray().apply {
            add(byteArrayOf(2, 3, 4))
            add(byteArrayOf(5, 6, 7))
        }

        val bytes = ByteArray(8) { i -> (i + 10).toByte() }

        // copy partial bytes
        baa.copyInto(
            destination = bytes,
            destinationOffset = 2,
            startIndex = 1,
            endIndex = 5
        )

        assertContentEquals(listOf(10, 11, 3, 4, 5, 6, 16, 17), bytes.toList())
    }

    @Test
    fun copyOfCopiesContentIndependently() {
        val baa = ByteArrayArray()
        baa.add(byteArrayOf(1, 2, 3))
        baa.add(byteArrayOf(4, 5))

        val copy = baa.copyOf()
        baa.add(byteArrayOf(6))
        copy.add(byteArrayOf(7, 8))

        assertEquals(6, baa.size)
        assertContentEquals(listOf<Byte>(1, 2, 3, 4, 5, 6), baa.toList())
        assertEquals(7, copy.size)
        assertContentEquals(listOf<Byte>(1, 2, 3, 4, 5, 7, 8), copy.toList())
    }

    @Test
    fun decodesWordsAcrossAddedArrays() {
        val baa = ByteArrayArray()
        baa.add(byteArrayOf(1, 2, 3))
        baa.add(byteArrayOf(4, 5, 6, 7, 8, 9))

        assertEquals(0x04030201, baa.decodeLEInt(0))
        assertEquals(0x02030405, baa.decodeBEInt(1))
        assertEquals(0x0908070605040302L, baa.decodeLELong(1))
    }

    @Test
    fun decodeRejectsWordsPastSizeEvenWithinCapacity() {
        // The backing array grows to at least 64 bytes, so these reads would fit it but not the 9-byte content
        val baa = ByteArrayArray()
        baa.add(ByteArray(9))

        assertEquals(0L, baa.decodeLELong(1))
        assertEquals(0, baa.decodeLEInt(5))

        val long = assertFailsWith<IndexOutOfBoundsException> { baa.decodeLELong(2) }
        assertEquals("Range 2..10 out of bounds for length 9", long.message)
        assertFailsWith<IndexOutOfBoundsException> { baa.decodeLEInt(6) }
        assertFailsWith<IndexOutOfBoundsException> { baa.decodeBEInt(6) }
        assertFailsWith<IndexOutOfBoundsException> { baa.decodeLEInt(-1) }
    }
}
