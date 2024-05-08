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

package com.appmattus.crypto.internal.core.uint

import kotlin.test.Test
import kotlin.test.assertEquals

class UInt128ConstructorTest {

    @Test
    fun testConstructorOne() {
        assertEquals(0u, 0x01U.toUByte().toUInt128().upper)
        assertEquals(0u, 0x0123U.toUShort().toUInt128().upper)
        assertEquals(0u, 0x01234567U.toUInt128().upper)
        assertEquals(0u, 0x0123456789abcdefUL.toUInt128().upper)

        assertEquals(0x01U, 0x01U.toUByte().toUInt128().lower)
        assertEquals(0x0123U, 0x0123U.toUShort().toUInt128().lower)
        assertEquals(0x01234567U, 0x01234567U.toUInt128().lower)
        assertEquals(0x0123456789abcdefUL, 0x0123456789abcdefUL.toUInt128().lower)
    }

    @Test
    fun testConstructorTwo() {
        for (hi in 0uL until 2uL) {
            for (lo in 0uL until 2uL) {
                val value = UInt128(hi, lo)
                assertEquals(hi, value.upper)
                assertEquals(lo, value.lower)
            }
        }

        assertEquals(0x01U, UInt128(0x01U, 0x01U).upper)
        assertEquals(0x0123U, UInt128(0x0123U, 0x0123U).upper)
        assertEquals(0x01234567U, UInt128(0x01234567U, 0x01234567U).upper)
        assertEquals(0x0123456789abcdefUL, UInt128(0x0123456789abcdefUL, 0x0123456789abcdefUL).upper)

        assertEquals(0x01U, UInt128(0x01U, 0x01U).lower)
        assertEquals(0x0123U, UInt128(0x0123U, 0x0123U).lower)
        assertEquals(0x01234567U, UInt128(0x01234567U, 0x01234567U).lower)
        assertEquals(0x0123456789abcdefUL, UInt128(0x0123456789abcdefUL, 0x0123456789abcdefUL).lower)
    }

    @Test
    fun testByteConstruction() {
        for (i in 0..Byte.MAX_VALUE) {
            val value = i.toByte().toUInt128()
            assertEquals(i.toULong() and 0xFFuL, value.lower)
            assertEquals(0uL, value.upper)
        }

        // Verify negative values apply sign extension
        for (i in Byte.MIN_VALUE until 0) {
            val value = i.toByte().toUInt128()
            assertEquals(i.toULong() and 0xFFuL or 0xFFFFFFFFFFFFFF00u, value.lower)
            assertEquals(ULong.MAX_VALUE, value.upper)
        }
    }

    @Test
    fun testShortConstruction() {
        for (i in 0..Short.MAX_VALUE) {
            val value = i.toShort().toUInt128()
            assertEquals(i.toULong() and 0xFFFFuL, value.lower)
            assertEquals(0uL, value.upper)
        }

        // Verify negative values apply sign extension
        for (i in Short.MIN_VALUE until 0) {
            val value = i.toShort().toUInt128()
            assertEquals(i.toULong() and 0xFFFFuL or 0xFFFFFFFFFFFF0000u, value.lower)
            assertEquals(ULong.MAX_VALUE, value.upper)
        }
    }

    @Test
    fun testIntConstruction() {
        for (i in 0..Int.MAX_VALUE step (Int.MAX_VALUE shr 8)) {
            val value = i.toUInt128()
            assertEquals(i.toULong() and 0xFFFFFFFFuL, value.lower)
            assertEquals(0uL, value.upper)
        }

        // Verify negative values apply sign extension
        for (i in Int.MIN_VALUE until 0 step (Int.MAX_VALUE shr 8)) {
            val value = i.toUInt128()
            assertEquals(i.toULong() and 0xFFFFFFFFuL or 0xFFFFFFFF00000000u, value.lower)
            assertEquals(ULong.MAX_VALUE, value.upper)
        }
    }

    @Test
    fun testLongConstruction() {
        for (i in 0..Long.MAX_VALUE step (Long.MAX_VALUE shr 8)) {
            val value = i.toUInt128()
            assertEquals(i.toULong() and 0xFFFFFFFFFFFFFFFFuL, value.lower)
            assertEquals(0uL, value.upper)
        }

        // Verify negative values apply sign extension
        for (i in Long.MIN_VALUE until 0 step (Long.MAX_VALUE shr 8)) {
            val value = i.toUInt128()
            assertEquals(i.toULong() and 0xFFFFFFFFFFFFFFFFuL, value.lower)
            assertEquals(ULong.MAX_VALUE, value.upper)
        }
    }

    @Test
    fun testUByteConstruction() {
        for (i in Byte.MIN_VALUE..Byte.MAX_VALUE) {
            val value = i.toUByte().toUInt128()
            assertEquals(i.toULong() and 0xFFuL, value.lower)
            assertEquals(0uL, value.upper)
        }
    }

    @Test
    fun testUShortConstruction() {
        for (i in UShort.MIN_VALUE..UShort.MAX_VALUE) {
            val value = i.toUShort().toUInt128()
            assertEquals(i.toULong() and 0xFFFFuL, value.lower)
            assertEquals(0u, value.upper)
        }
    }

    @Test
    fun testUIntConstruction() {
        for (i in UInt.MIN_VALUE..UInt.MAX_VALUE step (UInt.MAX_VALUE shr 8).toInt()) {
            val value = i.toUInt128()
            assertEquals(i.toULong() and 0xFFFFFFFFuL, value.lower)
            assertEquals(0u, value.upper)
        }
    }

    @Test
    fun testULongConstruction() {
        for (i in ULong.MIN_VALUE..ULong.MAX_VALUE step (ULong.MAX_VALUE shr 8).toLong()) {
            val value = i.toUInt128()
            assertEquals(i, value.lower)
            assertEquals(0u, value.upper)
        }
    }

    @Test
    fun testAccessors() {
        val value = UInt128(0xfedcba9876543210UL, 0x0123456789abcdefUL)
        assertEquals(0xfedcba9876543210UL, value.upper)
        assertEquals(0x0123456789abcdefUL, value.lower)
    }
}
