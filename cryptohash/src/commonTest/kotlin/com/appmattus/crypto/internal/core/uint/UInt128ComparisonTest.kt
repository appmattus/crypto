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

import com.appmattus.crypto.internal.core.uint.UInt128.Companion.MAX_VALUE
import com.appmattus.crypto.internal.core.uint.UInt128.Companion.ONE
import com.appmattus.crypto.internal.core.uint.UInt128.Companion.ZERO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class UInt128ComparisonTest {

    @Test
    fun testCompareToUByte() {
        assertEquals(0, ZERO.compareTo(0u.toUByte()))
        assertEquals(+1, ONE.compareTo(0u.toUByte()))
        assertEquals(-1, ZERO.compareTo(1u.toUByte()))
        assertEquals(+1, UInt128(1u, 0u).compareTo(1u.toUByte()))
        assertEquals(-1, ONE.compareTo(UByte.MAX_VALUE))
    }

    @Test
    fun testCompareToUShort() {
        assertEquals(0, ZERO.compareTo(0u.toUShort()))
        assertEquals(+1, ONE.compareTo(0u.toUShort()))
        assertEquals(-1, ZERO.compareTo(1u.toUShort()))
        assertEquals(+1, UInt128(1u, 0u).compareTo(1u.toUShort()))
        assertEquals(-1, ONE.compareTo(UShort.MAX_VALUE))
    }

    @Test
    fun testCompareToUInt() {
        assertEquals(0, ZERO.compareTo(0u))
        assertEquals(+1, ONE.compareTo(0u))
        assertEquals(-1, ZERO.compareTo(1u))
        assertEquals(+1, UInt128(1u, 0u).compareTo(1u))
        assertEquals(-1, ONE.compareTo(UInt.MAX_VALUE))
    }

    @Test
    fun testCompareToULong() {
        assertEquals(0, ZERO.compareTo(0uL))
        assertEquals(+1, ONE.compareTo(0uL))
        assertEquals(-1, ZERO.compareTo(1uL))
        assertEquals(+1, UInt128(1u, 0u).compareTo(1uL))
        assertEquals(-1, ONE.compareTo(ULong.MAX_VALUE))
    }

    @Test
    fun testCompareToUInt128() {
        assertEquals(0, ZERO.compareTo(ZERO))
        assertEquals(+1, ONE.compareTo(ZERO))
        assertEquals(-1, ZERO.compareTo(ONE))
        assertEquals(+1, UInt128(1u, 0u).compareTo(ONE))
        assertEquals(-1, ONE.compareTo(UInt128(1u, 0u)))
    }

    @Test
    fun testCompareToGreaterThan() {
        assertFalse(ZERO > ZERO)
        assertFalse(ZERO > MAX_VALUE)
        assertTrue(MAX_VALUE > ZERO)
        assertFalse(MAX_VALUE > MAX_VALUE)

        val uByteSmall = UByte.MIN_VALUE
        val uByteBig = UByte.MAX_VALUE
        assertFalse(ZERO > uByteSmall)
        assertFalse(ZERO > uByteBig)
        assertTrue(MAX_VALUE > uByteSmall)
        assertTrue(MAX_VALUE > uByteBig)

        val uShortSmall = UShort.MIN_VALUE
        val uShortBig = UShort.MAX_VALUE
        assertFalse(ZERO > uShortSmall)
        assertFalse(ZERO > uShortBig)
        assertTrue(MAX_VALUE > uShortSmall)
        assertTrue(MAX_VALUE > uShortBig)

        val uIntSmall = UInt.MIN_VALUE
        val uIntBig = UInt.MAX_VALUE
        assertFalse(ZERO > uIntSmall)
        assertFalse(ZERO > uIntBig)
        assertTrue(MAX_VALUE > uIntSmall)
        assertTrue(MAX_VALUE > uIntBig)

        val uLongSmall = ULong.MIN_VALUE
        val uLongBig = ULong.MAX_VALUE
        assertFalse(ZERO > uLongSmall)
        assertFalse(ZERO > uLongBig)
        assertTrue(MAX_VALUE > uLongSmall)
        assertTrue(MAX_VALUE > uLongBig)

        assertFalse(ZERO > ONE)
        assertFalse(ONE > MAX_VALUE)
        assertTrue(MAX_VALUE > ONE)
        assertTrue(ONE > ZERO)

        val i63 = UInt128(0u, 0x8000000000000000u)
        val i64 = i63 + i63
        val i65 = i64 + i64
        assertTrue(i64 > i63)
        assertTrue(i64 + i63 > i64)
        assertTrue(i65 > i64 + i63)
    }

    @Test
    fun testCompareToGreaterThanOrEquals() {
        assertTrue(ZERO >= ZERO)
        assertFalse(ZERO >= MAX_VALUE)
        assertTrue(MAX_VALUE >= ZERO)
        assertTrue(MAX_VALUE >= MAX_VALUE)

        val uByteSmall = UByte.MIN_VALUE
        val uByteBig = UByte.MAX_VALUE
        assertTrue(ZERO >= uByteSmall)
        assertFalse(ZERO >= uByteBig)
        assertTrue(MAX_VALUE >= uByteSmall)
        assertTrue(MAX_VALUE >= uByteBig)

        val uShortSmall = UShort.MIN_VALUE
        val uShortBig = UShort.MAX_VALUE
        assertTrue(ZERO >= uShortSmall)
        assertFalse(ZERO >= uShortBig)
        assertTrue(MAX_VALUE >= uShortSmall)
        assertTrue(MAX_VALUE >= uShortBig)

        val uIntSmall = UInt.MIN_VALUE
        val uIntBig = UInt.MAX_VALUE
        assertTrue(ZERO >= uIntSmall)
        assertFalse(ZERO >= uIntBig)
        assertTrue(MAX_VALUE >= uIntSmall)
        assertTrue(MAX_VALUE >= uIntBig)

        val uLongSmall = ULong.MIN_VALUE
        val uLongBig = ULong.MAX_VALUE
        assertTrue(ZERO >= uLongSmall)
        assertFalse(ZERO >= uLongBig)
        assertTrue(MAX_VALUE >= uLongSmall)
        assertTrue(MAX_VALUE >= uLongBig)
    }

    @Test
    fun testCompareToLessThan() {
        assertFalse(ZERO < ZERO)
        assertTrue(ZERO < MAX_VALUE)
        assertFalse(MAX_VALUE < ZERO)
        assertFalse(MAX_VALUE < MAX_VALUE)

        val uByteSmall = UByte.MIN_VALUE
        val uByteBig = UByte.MAX_VALUE
        assertFalse(ZERO < uByteSmall)
        assertTrue(ZERO < uByteBig)
        assertFalse(MAX_VALUE < uByteSmall)
        assertFalse(MAX_VALUE < uByteBig)

        val uShortSmall = UShort.MIN_VALUE
        val uShortBig = UShort.MAX_VALUE
        assertFalse(ZERO < uShortSmall)
        assertTrue(ZERO < uShortBig)
        assertFalse(MAX_VALUE < uShortSmall)
        assertFalse(MAX_VALUE < uShortBig)

        val uIntSmall = UInt.MIN_VALUE
        val uIntBig = UInt.MAX_VALUE
        assertFalse(ZERO < uIntSmall)
        assertTrue(ZERO < uIntBig)
        assertFalse(MAX_VALUE < uIntSmall)
        assertFalse(MAX_VALUE < uIntBig)

        val uLongSmall = ULong.MIN_VALUE
        val uLongBig = ULong.MAX_VALUE
        assertFalse(ZERO < uLongSmall)
        assertTrue(ZERO < uLongBig)
        assertFalse(MAX_VALUE < uLongSmall)
        assertFalse(MAX_VALUE < uLongBig)

        assertTrue(ZERO < ONE)
        assertTrue(ONE < MAX_VALUE)
        assertFalse(MAX_VALUE < ONE)
        assertFalse(ONE < ZERO)

        val i63 = UInt128(0u, 0x8000000000000000u)
        val i64 = i63 + i63
        val i65 = i64 + i64
        assertFalse(i64 < i63)
        assertFalse(i64 + i63 < i64)
        assertFalse(i65 < i64 + i63)
    }

    @Test
    fun testCompareToLessThanOrEquals() {
        assertTrue(ZERO <= ZERO)
        assertTrue(ZERO <= MAX_VALUE)
        assertFalse(MAX_VALUE <= ZERO)
        assertTrue(MAX_VALUE <= MAX_VALUE)

        val uByteSmall = UByte.MIN_VALUE
        val uByteBig = UByte.MAX_VALUE
        assertTrue(ZERO <= uByteSmall)
        assertTrue(ZERO <= uByteBig)
        assertFalse(MAX_VALUE <= uByteSmall)
        assertFalse(MAX_VALUE <= uByteBig)

        val uShortSmall = UShort.MIN_VALUE
        val uShortBig = UShort.MAX_VALUE
        assertTrue(ZERO <= uShortSmall)
        assertTrue(ZERO <= uShortBig)
        assertFalse(MAX_VALUE <= uShortSmall)
        assertFalse(MAX_VALUE <= uShortBig)

        val uIntSmall = UInt.MIN_VALUE
        val uIntBig = UInt.MAX_VALUE
        assertTrue(ZERO <= uIntSmall)
        assertTrue(ZERO <= uIntBig)
        assertFalse(MAX_VALUE <= uIntSmall)
        assertFalse(MAX_VALUE <= uIntBig)

        val uLongSmall = ULong.MIN_VALUE
        val uLongBig = ULong.MAX_VALUE
        assertTrue(ZERO <= uLongSmall)
        assertTrue(ZERO <= uLongBig)
        assertFalse(MAX_VALUE <= uLongSmall)
        assertFalse(MAX_VALUE <= uLongBig)
    }

    @Test
    fun testEquals() {
        @Suppress("RemoveExplicitTypeArguments")
        (assertNotEquals<UInt128?>(ZERO, null))
        assertEquals(ZERO, ZERO)
        assertEquals(0xdeadbeefUL.toUInt128(), 0xdeadbeefUL.toUInt128())
        assertNotEquals(0xdeadbeefUL.toUInt128(), 0xfee1baadUL.toUInt128())

        val i63a = UInt128(0u, 0x8000000000000000uL)
        val i63b = UInt128(0u, 0x8000000000000000uL)
        assertEquals(i63a, i63b)
        assertNotEquals(i63a, i63a + i63b)
        assertNotEquals(i63a, ZERO)

        assertTrue(UInt128Test.u8 != UInt128Test.u64)
        assertTrue(UInt128Test.u16 != UInt128Test.u32)
        assertTrue(UInt128Test.u32 != UInt128Test.u16)
        assertTrue(UInt128Test.u64 != UInt128Test.u8)

        assertFalse(UInt128Test.u8 != 0xaaUL.toUInt128())
        assertFalse(UInt128Test.u16 != 0xaaaaUL.toUInt128())
        assertFalse(UInt128Test.u32 != 0xaaaaaaaaUL.toUInt128())
        assertFalse(UInt128Test.u64 != 0xaaaaaaaaaaaaaaaaUL.toUInt128())
    }
}
