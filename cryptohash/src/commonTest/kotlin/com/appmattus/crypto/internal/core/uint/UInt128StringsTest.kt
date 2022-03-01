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
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class UInt128StringsTest {

    private val expected = UInt128(0xfedcba9876543210UL, 0xfedcba9876543210UL)

    @Test
    fun testToString() {
        val tests = listOf(
            2 to "10000100000101011000010101101100",
            3 to "12201102210121112101",
            4 to "2010011120111230",
            5 to "14014244043144",
            6 to "1003520344444",
            7 to "105625466632",
            8 to "20405302554",
            9 to "5642717471",
            10 to "2216002924",
            11 to "a3796a883",
            12 to "51a175124",
            13 to "294145645",
            14 to "170445352",
            15 to "ce82d6d4",
            16 to "8415856c",
        )

        // make sure all of the test strings create the ASCII version of the string
        val original = 2216002924.toUInt128()
        for (t in tests) {
            assertEquals(t.second, original.toString(t.first))
        }

        val value = 0xfedcba9876543210UL.toUInt128()
        // octal
        assertEquals("1773345651416625031020", value.toString(8))
        // decimal
        assertEquals("18364758544493064720", value.toString(10))
        // hex
        assertEquals("fedcba9876543210", value.toString(16))

        assertEquals("0", UInt128.ZERO.toString())
    }

    @Test
    fun testHexStringToUInt128() {
        assertEquals(expected, "fedcba9876543210fedcba9876543210".toUInt128(16))
        assertFails { "1fedcba9876543210fedcba9876543210".toUInt128(16) }

        assertNotNull("fedcba9876543210fedcba9876543210".toUInt128OrNull(16))
        assertNull("1fedcba9876543210fedcba9876543210".toUInt128OrNull(16))
    }

    @Test
    fun testDecStringToUInt128() {
        assertEquals(expected, "338770000845734292534325025077361652240".toUInt128())
        assertFails { "1338770000845734292534325025077361652240".toUInt128() }

        assertNotNull("338770000845734292534325025077361652240".toUInt128OrNull())
        assertNull("1338770000845734292534325025077361652240".toUInt128OrNull())
    }

    @Test
    fun testOctStringToUInt128() {
        assertEquals(expected, "3766713523035452062041773345651416625031020".toUInt128(8))
        assertFails { "13766713523035452062041773345651416625031020".toUInt128(8) }

        assertNotNull("3766713523035452062041773345651416625031020".toUInt128OrNull(8))
        assertNull("13766713523035452062041773345651416625031020".toUInt128OrNull(8))
    }

    @Test
    fun testBinStringToUInt128() {
        val value =
            "11111110110111001011101010011000011101100101010000110010000100001111111011011100101110101001100001110110010101000011001000010000"
                .toUInt128(2)
        assertEquals(expected, value)
        assertFails {
            "111111110110111001011101010011000011101100101010000110010000100001111111011011100101110101001100001110110010101000011001000010000"
                .toUInt128(2)
        }

        assertNotNull(
            "11111110110111001011101010011000011101100101010000110010000100001111111011011100101110101001100001110110010101000011001000010000"
                .toUInt128OrNull(2)
        )
        assertNull(
            "111111110110111001011101010011000011101100101010000110010000100001111111011011100101110101001100001110110010101000011001000010000"
                .toUInt128OrNull(2)
        )
    }
}
