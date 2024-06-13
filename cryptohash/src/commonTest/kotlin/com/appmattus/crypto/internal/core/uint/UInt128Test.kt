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
import kotlin.test.assertFails
import kotlin.test.assertSame

class UInt128Test {

    @Test
    fun testPlus() {
        val value = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL)

        assertEquals(expected = ZERO, actual = ZERO + ZERO)
        assertEquals(expected = ONE, actual = ONE + ZERO)
        assertEquals(expected = ONE, actual = ZERO + ONE)
        assertEquals(expected = UInt128(1u, 1u), actual = UInt128(1u, 0u) + ONE)
        assertEquals(expected = UInt128(1u, 1u), actual = ONE + UInt128(1u, 0u))
        assertEquals(expected = UInt128(1u, 0u), actual = UInt128(0u, ULong.MAX_VALUE) + ONE)
        assertEquals(expected = UInt128(0u, 2u), actual = ONE + ONE)
        assertEquals(expected = UInt128(2u, 0u), actual = UInt128(1u, 0u) + UInt128(1u, 0u))
        assertEquals(expected = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f19aUL), actual = u8 + value)
        assertEquals(expected = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f19b9aUL), actual = u16 + value)
        assertEquals(expected = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f19b9b9b9aUL), actual = u32 + value)
        assertEquals(expected = UInt128(0xf0f0f0f0f0f0f0f1UL, 0x9b9b9b9b9b9b9b9aUL), actual = u64 + value)
        assertEquals(expected = MAX_VALUE, actual = ZERO + MAX_VALUE)
        assertEquals(expected = ZERO, actual = MAX_VALUE + ONE)
        assertEquals(expected = UInt128(ULong.MAX_VALUE, ULong.MAX_VALUE - 1u), actual = MAX_VALUE + MAX_VALUE)
        assertEquals(expected = UInt128(1u, 0u), actual = UInt128(0u, ULong.MAX_VALUE) + ONE)

        // Numbers
        assertEquals(expected = UInt128(1u, 1u), actual = UInt128(1u, 0u) + 1u.toUByte())
        assertEquals(expected = UInt128(1u, 1u), actual = UInt128(1u, 0u) + 1u.toUShort())
        assertEquals(expected = UInt128(1u, 1u), actual = UInt128(1u, 0u) + 1u)
        assertEquals(expected = UInt128(1u, 1u), actual = UInt128(1u, 0u) + 1uL)
    }

    @Test
    fun testMinus() {
        val value = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL)

        assertEquals(ZERO, ZERO - ZERO)
        assertEquals(ONE, ONE - ZERO)
        assertEquals(MAX_VALUE, ZERO - ONE)
        assertEquals(ZERO, ONE - ONE)
        assertEquals(ZERO, MAX_VALUE - MAX_VALUE)
        assertEquals(ONE, ZERO - MAX_VALUE)
        assertEquals(UInt128(0u, ULong.MAX_VALUE), UInt128(1u, 0u) - ONE)
        assertEquals(UInt128(ULong.MAX_VALUE, 1u), ONE - UInt128(1u, 0u))
        assertEquals(UInt128(0u, 0xFFFFFFFFFFFFFFFEu), UInt128(0u, ULong.MAX_VALUE) - ONE)
        assertEquals(UInt128(ULong.MAX_VALUE, 0xFFFFFFFFFFFFFFFEu), MAX_VALUE - ONE)
        assertEquals(UInt128(0u, 2u), ONE - MAX_VALUE)
        assertEquals(UInt128(0xffffffffffffffffUL, 0xfffffffffffffffeUL), MAX_VALUE - ONE)
        assertEquals(UInt128(0x0f0f0f0f0f0f0f0fUL, 0x0f0f0f0f0f0f0fbaUL), u8 - value)
        assertEquals(UInt128(0x0f0f0f0f0f0f0f0fUL, 0x0f0f0f0f0f0fb9baUL), u16 - value)
        assertEquals(UInt128(0x0f0f0f0f0f0f0f0fUL, 0x0f0f0f0fb9b9b9baUL), u32 - value)
        assertEquals(UInt128(0x0f0f0f0f0f0f0f0fUL, 0xb9b9b9b9b9b9b9baUL), u64 - value)

        // Numbers
        assertEquals(UInt128(ULong.MAX_VALUE, 0xFFFFFFFFFFFFFFFEu), MAX_VALUE - 1u.toUByte())
        assertEquals(UInt128(ULong.MAX_VALUE, 0xFFFFFFFFFFFFFFFEu), MAX_VALUE - 1u.toUShort())
        assertEquals(UInt128(ULong.MAX_VALUE, 0xFFFFFFFFFFFFFFFEu), MAX_VALUE - 1u)
        assertEquals(UInt128(ULong.MAX_VALUE, 0xFFFFFFFFFFFFFFFEu), MAX_VALUE - 1uL)
    }

    @Test
    fun testTimes() {
        val value = 0xfedbca9876543210UL.toUInt128()
        val value0 = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL)

        assertEquals(ZERO, ZERO * ONE)
        assertEquals(ZERO, ONE * ZERO)
        assertEquals(MAX_VALUE, ONE * MAX_VALUE)
        assertEquals(MAX_VALUE, MAX_VALUE * ONE)
        assertEquals(ONE, MAX_VALUE * MAX_VALUE)
        assertEquals(ZERO, value * ZERO)
        assertEquals(ZERO, ZERO * value)
        assertEquals(value, value * ONE)
        assertEquals(value, ONE * value)
        assertEquals(UInt128(0xfdb8e2bacbfe7cefUL, 0x010e6cd7a44a4100UL), value * value)
        assertEquals(UInt128(0xffffffffffffffffuL, 0xffffffffffffff60UL), u8 * value0)
        assertEquals(UInt128(0xffffffffffffffffuL, 0xffffffffffff5f60UL), u16 * value0)
        assertEquals(UInt128(0xffffffffffffffffuL, 0xffffffff5f5f5f60UL), u32 * value0)
        assertEquals(UInt128(0xffffffffffffffffuL, 0x5f5f5f5f5f5f5f60UL), u64 * value0)
        assertEquals((12345678L * 13L).toUInt128(), 12345678uL.toUInt128() * 13uL.toUInt128())

        // Numbers
        assertEquals(value, value * 1u.toUByte())
        assertEquals(value, value * 1u.toUShort())
        assertEquals(value, value * 1u)
        assertEquals(value, value * 1uL)
    }

    @Test
    fun testDiv() {
        val bigValue = 0xfedbca9876543210UL.toUInt128()
        val smallValue = 0xffffUL.toUInt128()
        val value = 0x7bUL.toUInt128()

        assertEquals(ZERO, ZERO / ONE)
        assertEquals(ZERO, ONE / MAX_VALUE)
        assertEquals(MAX_VALUE, MAX_VALUE / ONE)
        assertEquals(ONE, MAX_VALUE / MAX_VALUE)
        assertEquals(1.toUInt128(), smallValue / smallValue)
        assertEquals(0.toUInt128(), smallValue / bigValue)
        assertEquals(1.toUInt128(), bigValue / bigValue)
        assertEquals(0x1UL.toUInt128(), u8 / value)
        assertEquals(0x163UL.toUInt128(), u16 / value)
        assertEquals(0x163356bUL.toUInt128(), u32 / value)
        assertEquals(0x163356b88ac0de0UL.toUInt128(), u64 / value)
        assertEquals((12345678L / 13L).toUInt128(), 12345678uL.toUInt128() / 13uL.toUInt128())

        // division by zero
        assertFails { 1.toUInt128() / 0.toUInt128() }

        // Numbers
        assertEquals(MAX_VALUE, MAX_VALUE / 1u.toUByte())
        assertEquals(MAX_VALUE, MAX_VALUE / 1u.toUShort())
        assertEquals(MAX_VALUE, MAX_VALUE / 1u)
        assertEquals(MAX_VALUE, MAX_VALUE / 1uL)
    }

    @Test
    fun testRem() {
        val value = UInt128(0xffffffffffffffffUL, 0xffffffffffffffffUL)
        val value1 = 0xd03UL.toUInt128()
        val valueMod = 0xfedcba9876543210UL

        assertEquals(ZERO, ZERO % ONE)
        assertEquals(ONE, ONE % MAX_VALUE)
        assertEquals(ZERO, MAX_VALUE % ONE)
        assertEquals(ONE, MAX_VALUE % 2u.toUInt128())
        assertEquals(ONE, ONE % 2u.toUInt128())
        assertEquals(0xaaUL.toUInt128(), u8 % value1)
        assertEquals(0x183UL.toUInt128(), u16 % value1)
        assertEquals(0x249UL.toUInt128(), u32 % value1)
        assertEquals(0xc7fUL.toUInt128(), u64 % value1)
        assertEquals(0x7f598f328cc265bfUL.toUInt128(), value % valueMod)
        assertEquals(ZERO, UInt128(0xfedcba9876543210u, 0u) % valueMod)
        assertEquals((12345678L % 13L).toUInt128(), 12345678L.toUInt128() % 13L.toUInt128())

        assertFails { ONE % ZERO }

        // Numbers
        assertEquals(ZERO, MAX_VALUE % 1u.toUByte())
        assertEquals(ZERO, MAX_VALUE % 1u.toUShort())
        assertEquals(ZERO, MAX_VALUE % 1u)
        assertEquals(ZERO, MAX_VALUE % 1uL)
        assertEquals(ONE, ONE % 2u.toUByte())
        assertEquals(ONE, ONE % 2u.toUShort())
        assertEquals(ONE, ONE % 2u)
        assertEquals(ONE, ONE % 2uL)
    }

    @Test
    fun testFloorDiv() {
        val bigValue = 0xfedbca9876543210UL.toUInt128()
        val smallValue = 0xffffUL.toUInt128()
        val value = 0x7bUL.toUInt128()

        assertEquals(ZERO, ZERO.floorDiv(ONE))
        assertEquals(ZERO, ONE.floorDiv(MAX_VALUE))
        assertEquals(MAX_VALUE, MAX_VALUE.floorDiv(ONE))
        assertEquals(ONE, MAX_VALUE.floorDiv(MAX_VALUE))
        assertEquals(1.toUInt128(), smallValue.floorDiv(smallValue))
        assertEquals(0.toUInt128(), smallValue.floorDiv(bigValue))
        assertEquals(1.toUInt128(), bigValue.floorDiv(bigValue))
        assertEquals(0x1UL.toUInt128(), u8.floorDiv(value))
        assertEquals(0x163UL.toUInt128(), u16.floorDiv(value))
        assertEquals(0x163356bUL.toUInt128(), u32.floorDiv(value))
        assertEquals(0x163356b88ac0de0UL.toUInt128(), u64.floorDiv(value))
        assertEquals((12345678L.floorDiv(13L)).toUInt128(), 12345678uL.toUInt128().floorDiv(13uL.toUInt128()))

        // division by zero
        assertFails { 1.toUInt128().floorDiv(0.toUInt128()) }

        // Numbers
        assertEquals(MAX_VALUE, MAX_VALUE.floorDiv(1u.toUByte()))
        assertEquals(MAX_VALUE, MAX_VALUE.floorDiv(1u.toUShort()))
        assertEquals(MAX_VALUE, MAX_VALUE.floorDiv(1u))
        assertEquals(MAX_VALUE, MAX_VALUE.floorDiv(1uL))
    }

    @Test
    fun testMod() {
        val value = UInt128(0xffffffffffffffffUL, 0xffffffffffffffffUL)
        val value1 = 0xd03UL.toUInt128()
        val valueMod = 0xfedcba9876543210UL

        assertEquals(ZERO, ZERO.mod(ONE))
        assertEquals(ONE, ONE.mod(MAX_VALUE))
        assertEquals(ZERO, MAX_VALUE.mod(ONE))
        assertEquals(ONE, MAX_VALUE.mod(2u.toUInt128()))
        assertEquals(ONE, ONE.mod(2u.toUInt128()))
        assertEquals(0xaaUL.toUInt128(), u8.mod(value1))
        assertEquals(0x183UL.toUInt128(), u16.mod(value1))
        assertEquals(0x249UL.toUInt128(), u32.mod(value1))
        assertEquals(0xc7fUL.toUInt128(), u64.mod(value1))
        assertEquals(0x7f598f328cc265bfUL, value.mod(valueMod))
        assertEquals(0uL, UInt128(0xfedcba9876543210u, 0u).mod(valueMod))
        assertEquals((12345678L % 13L).toUInt128(), 12345678L.toUInt128().mod(13L.toUInt128()))

        assertFails { ONE.mod(ZERO) }

        // Numbers
        assertEquals(0u, MAX_VALUE.mod(1u.toUByte()))
        assertEquals(0u, MAX_VALUE.mod(1u.toUShort()))
        assertEquals(0u, MAX_VALUE.mod(1u))
        assertEquals(0u, MAX_VALUE.mod(1uL))
        assertEquals(1u, ONE.mod(2u.toUByte()))
        assertEquals(1u, ONE.mod(2u.toUShort()))
        assertEquals(1u, ONE.mod(2u))
        assertEquals(1u, ONE.mod(2uL))
    }

    @Test
    fun testInc() {
        var value = MAX_VALUE
        assertEquals(0u.toUInt128(), ++value)
        assertEquals(0u.toUInt128(), value++)
        assertEquals(2u.toUInt128(), ++value)
    }

    @Test
    fun testDec() {
        var value = 0u.toUInt128()
        assertEquals(MAX_VALUE, --value)
        assertEquals(MAX_VALUE, value--)
        assertEquals(UInt128(0xffffffffffffffffUL, 0xfffffffffffffffdUL), --value)
    }

    @Test
    fun testShl() {
        assertEquals(ZERO, ZERO shl 1)
        assertEquals(UInt128(ULong.MAX_VALUE, ULong.MAX_VALUE - 1u), MAX_VALUE shl 1)
        assertEquals(UInt128(0uL, 2uL), ONE shl 1)
        assertEquals(UInt128(1uL, 0uL), UInt128(0uL, (1uL shl (ULong.SIZE_BITS - 1))) shl 1)
        assertEquals(ONE, ONE shl UInt128.SIZE_BITS)
        assertEquals(ONE, ONE shl -UInt128.SIZE_BITS)
        assertEquals((2uL shl -1).toUInt128(), 2u.toUInt128() shl -1)

        for (i in 0 until 64) {
            assertEquals((1uL shl i).toUInt128(), ONE shl i)
            assertEquals(0.toUInt128(), ZERO shl i)
        }

        for (i in 0 until UInt128.SIZE_BITS) {
            val powNum = 2u.toUInt128().pow(i)
            val shiftNum = ONE shl i
            assertEquals(powNum, shiftNum)
        }
    }

    @Test
    fun testShr() {
        val highBit = 1u.toUInt128().rotateRight(1)

        assertEquals(ZERO, ZERO shr 1)
        assertEquals(UInt128(0x7FFFFFFFFFFFFFFFuL, ULong.MAX_VALUE), MAX_VALUE shr 1)
        assertEquals(ZERO, ONE shr 1)
        assertEquals(ONE, UInt128(0uL, 2uL) shr 1)
        assertEquals(UInt128(0uL, 0x8000000000000000uL), UInt128(1uL, 0uL) shr 1)
        assertEquals(highBit, highBit shr UInt128.SIZE_BITS)
        assertEquals(highBit, highBit shr -UInt128.SIZE_BITS)
        assertEquals((1uL shr -1).toUInt128(), ONE shr -1)

        val value = ULong.MAX_VALUE.toUInt128()
        for (i in 0 until 64) {
            assertEquals((ULong.MAX_VALUE shr i).toUInt128(), value shr i)
            assertEquals(0.toUInt128(), ZERO shr i)
        }

        for (i in 0 until UInt128.SIZE_BITS) {
            val powNum = 2u.toUInt128().pow(UInt128.SIZE_BITS - (i + 1))
            val shiftNum = highBit shr i
            assertEquals(powNum, shiftNum)
        }
    }

    @Test
    fun testAnd() {
        val value = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL)

        assertEquals(ONE, MAX_VALUE and ONE)
        assertEquals(UInt128(1u, 0u), MAX_VALUE and UInt128(1u, 0u))
        assertEquals(ZERO, MAX_VALUE and ZERO)
        assertEquals(0xa0UL.toUInt128(), u8 and value)
        assertEquals(0xa0a0UL.toUInt128(), u16 and value)
        assertEquals(0xa0a0a0a0UL.toUInt128(), u32 and value)
        assertEquals(0xa0a0a0a0a0a0a0a0UL.toUInt128(), u64 and value)
    }

    @Test
    fun testOr() {
        val value = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL)

        assertEquals(ONE, ZERO or ONE)
        assertEquals(ONE, ONE or ONE)
        assertEquals(UInt128(1u, 0u), ZERO or UInt128(1u, 0u))
        assertEquals(UInt128(1u, 0u), UInt128(1u, 0u) or UInt128(1u, 0u))
        assertEquals(MAX_VALUE, ZERO or MAX_VALUE)
        assertEquals(MAX_VALUE, MAX_VALUE or MAX_VALUE)
        assertEquals(value, ZERO or value)
        assertEquals(value, value or ZERO)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0faUL), u8 or value)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0fafaUL), u16 or value)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0fafafafaUL), u32 or value)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0xfafafafafafafafaUL), u64 or value)
    }

    @Test
    fun testXor() {
        val value = UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL)

        assertEquals(ONE, ZERO xor ONE)
        assertEquals(ZERO, ONE xor ONE)
        assertEquals(UInt128(1u, 0u), ZERO xor UInt128(1u, 0u))
        assertEquals(ZERO, UInt128(1u, 0u) xor UInt128(1u, 0u))
        assertEquals(MAX_VALUE, ZERO xor MAX_VALUE)
        assertEquals(ZERO, MAX_VALUE xor MAX_VALUE)
        assertEquals(value, ZERO xor value)
        assertEquals(ZERO, value xor value)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f05aUL), u8 xor value)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f05a5aUL), u16 xor value)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f05a5a5a5aUL), u32 xor value)
        assertEquals(UInt128(0xf0f0f0f0f0f0f0f0UL, 0x5a5a5a5a5a5a5a5aUL), u64 xor value)
    }

    @Test
    fun testInv() {
        assertEquals(UInt128(0xffffffffffffffffUL, 0xffffffffffffffffUL), UInt128(0x0000000000000000UL, 0x0000000000000000UL).inv())
        assertEquals(UInt128(0xffffffffffffffffUL, 0x0000000000000000UL), UInt128(0x0000000000000000UL, 0xffffffffffffffffUL).inv())
        assertEquals(UInt128(0x0000000000000000UL, 0x0000000000000000UL), UInt128(0xffffffffffffffffUL, 0xffffffffffffffffUL).inv())
    }

    @Test
    fun testUnaryPlus() {
        val value = 0x12345UL.toUInt128()
        assertEquals(value, +value)
    }

    @Test
    fun testUnaryMinus() {
        val value = ONE
        val neg = -value
        assertEquals(neg, -value)
        assertEquals(value, -neg)
        assertEquals(UInt128(0xffffffffffffffffUL, 0xffffffffffffffffUL), neg)
    }

    @Test
    fun testToByte() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(8, value1.toByte())
        assertEquals(-1, value2.toByte())
    }

    @Test
    fun testToShort() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(1800, value1.toShort())
        assertEquals(-257, value2.toShort())
    }

    @Test
    fun testToInt() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(84281096, value1.toInt())
        assertEquals(-50462977, value2.toInt())
    }

    @Test
    fun testToLong() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(72623859790382856L, value1.toLong())
        assertEquals(-506097522914230529L, value2.toLong())
    }

    @Test
    fun testToUByte() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(8u, value1.toUByte())
        assertEquals(255u, value2.toUByte())
    }

    @Test
    fun testToUShort() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(1800u, value1.toUShort())
        assertEquals(65279u, value2.toUShort())
    }

    @Test
    fun testToUInt() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(84281096u, value1.toUInt())
        assertEquals(4244504319u, value2.toUInt())
    }

    @Test
    fun testToULong() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)
        val value2 = UInt128(0x0102030405060708uL, 0xf8f9fafbfcfdfeffuL)

        assertEquals(72623859790382856uL, value1.toULong())
        assertEquals(17940646550795321087uL, value2.toULong())
    }

    @Test
    fun testToUInt128() {
        val value1 = UInt128(0xf8f9fafbfcfdfeffuL, 0x0102030405060708uL)

        assertEquals(value1, value1.toUInt128())
        assertSame(value1, value1.toUInt128())
    }

    companion object {
        val u8 = 0xaaUL.toUInt128()
        val u16 = 0xaaaaUL.toUInt128()
        val u32 = 0xaaaaaaaaUL.toUInt128()
        val u64 = 0xaaaaaaaaaaaaaaaaUL.toUInt128()
    }
}
