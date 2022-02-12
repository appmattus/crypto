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
}
