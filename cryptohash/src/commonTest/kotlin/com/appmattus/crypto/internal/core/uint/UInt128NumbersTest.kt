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

import com.appmattus.crypto.internal.core.uint.UInt128
import com.appmattus.crypto.internal.core.uint.UInt128.Companion.MAX_VALUE
import com.appmattus.crypto.internal.core.uint.UInt128.Companion.ONE
import com.appmattus.crypto.internal.core.uint.UInt128.Companion.ZERO
import com.appmattus.crypto.internal.core.uint.countLeadingZeroBits
import com.appmattus.crypto.internal.core.uint.countOneBits
import com.appmattus.crypto.internal.core.uint.countTrailingZeroBits
import com.appmattus.crypto.internal.core.uint.rotateLeft
import com.appmattus.crypto.internal.core.uint.rotateRight
import com.appmattus.crypto.internal.core.uint.takeHighestOneBit
import com.appmattus.crypto.internal.core.uint.takeLowestOneBit
import com.appmattus.crypto.internal.core.uint.toUInt128
import kotlin.test.Test
import kotlin.test.assertEquals

class UInt128NumbersTest {

    @Test
    fun testCountOneBits() {
        assertEquals(128, MAX_VALUE.countOneBits())
        assertEquals(0, ZERO.countOneBits())
        assertEquals(1, ONE.countOneBits())
        assertEquals(1, UInt128(1u, 0u).countOneBits())
        assertEquals(64, UInt128(ULong.MAX_VALUE, 0u).countOneBits())
        assertEquals(64, UInt128(0u, ULong.MAX_VALUE).countOneBits())
        assertEquals(3, "00000000001010100000".toUInt128(2).countOneBits())
        assertEquals(
            64,
            "10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010"
                .toUInt128(2).countOneBits()
        )
    }

    @Test
    fun testCountLeadingZeroBits() {
        assertEquals(0, MAX_VALUE.countLeadingZeroBits())
        assertEquals(63, UInt128(1u, 0u).countLeadingZeroBits())
        assertEquals(64, UInt128(0u, ULong.MAX_VALUE).countLeadingZeroBits())
        assertEquals(127, ONE.countLeadingZeroBits())
        assertEquals(128, ZERO.countLeadingZeroBits())
    }

    @Test
    fun testCountTrailingZeroBits() {
        assertEquals(0, MAX_VALUE.countTrailingZeroBits())
        assertEquals(64, UInt128(1u, 0u).countTrailingZeroBits())
        assertEquals(0, UInt128(0u, ULong.MAX_VALUE).countTrailingZeroBits())
        assertEquals(0, ONE.countTrailingZeroBits())
        assertEquals(128, ZERO.countTrailingZeroBits())
    }

    @Test
    fun testTakeHighestOneBit() {
        assertEquals(ONE shl 127, MAX_VALUE.takeHighestOneBit())
        assertEquals(ONE shl 64, UInt128(1u, 0u).takeHighestOneBit())
        assertEquals(ONE shl 63, UInt128(0u, ULong.MAX_VALUE).takeHighestOneBit())
        assertEquals(ONE, ONE.takeHighestOneBit())
        assertEquals(ZERO, ZERO.takeHighestOneBit())
    }

    @Test
    fun testTakeLowestOneBit() {
        assertEquals(ONE, MAX_VALUE.takeLowestOneBit())
        assertEquals(ONE shl 64, UInt128(1u, 0u).takeLowestOneBit())
        assertEquals(ONE, UInt128(0u, ULong.MAX_VALUE).takeLowestOneBit())
        assertEquals(ONE, ONE.takeLowestOneBit())
        assertEquals(ZERO, ZERO.takeLowestOneBit())
        assertEquals(ONE shl 127, UInt128(1uL shl 63, 0u).takeLowestOneBit())
    }

    @Test
    fun testRotateLeft() {
        val value = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)

        assertEquals(UInt128(0xf9fafbfcfdfeff01uL, 0x02030405060708f8uL), value.rotateLeft(8))
        assertEquals(UInt128(0xfcfdfeff01020304uL, 0x05060708f8f9fafbuL), value.rotateLeft(32))
        assertEquals(UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL), value.rotateLeft(64))
        assertEquals(UInt128(0x05060708f8f9fafbuL, 0xfcfdfeff01020304uL), value.rotateLeft(96))
        assertEquals(UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL), value.rotateLeft(128))

        assertEquals(UInt128(0x08f8f9fafbfcfdfeuL, 0xff01020304050607uL), value.rotateLeft(-8))
        assertEquals(UInt128(0x05060708f8f9fafbuL, 0xfcfdfeff01020304uL), value.rotateLeft(-32))
        assertEquals(UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL), value.rotateLeft(-64))
        assertEquals(UInt128(0xfcfdfeff01020304uL, 0x05060708f8f9fafbuL), value.rotateLeft(-96))
        assertEquals(UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL), value.rotateLeft(-128))
    }

    @Test
    fun testRotateRight() {
        val value = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)

        assertEquals(UInt128(0x08f8f9fafbfcfdfeuL, 0xff01020304050607uL), value.rotateRight(8))
        assertEquals(UInt128(0x05060708f8f9fafbuL, 0xfcfdfeff01020304uL), value.rotateRight(32))
        assertEquals(UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL), value.rotateRight(64))
        assertEquals(UInt128(0xfcfdfeff01020304uL, 0x05060708f8f9fafbuL), value.rotateRight(96))
        assertEquals(UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL), value.rotateRight(128))

        assertEquals(UInt128(0xf9fafbfcfdfeff01uL, 0x02030405060708f8uL), value.rotateRight(-8))
        assertEquals(UInt128(0xfcfdfeff01020304uL, 0x05060708f8f9fafbuL), value.rotateRight(-32))
        assertEquals(UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL), value.rotateRight(-64))
        assertEquals(UInt128(0x05060708f8f9fafbuL, 0xfcfdfeff01020304uL), value.rotateRight(-96))
        assertEquals(UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL), value.rotateRight(-128))
    }
}
