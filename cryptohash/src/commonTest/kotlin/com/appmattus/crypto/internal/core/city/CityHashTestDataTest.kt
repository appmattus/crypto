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

package com.appmattus.crypto.internal.core.city

import kotlin.test.Test
import kotlin.test.assertContentEquals

class CityHashTestDataTest {

    @Test
    fun matchesTheULongGenerator() {
        // Long enough for the carries and the counter to reach every part of both words
        val size = 1 shl 16
        val expected = ByteArray(size)
        var a: ULong = 9u
        var b: ULong = 777u
        for (i in 0 until size) {
            a += b
            b += a
            a = (a xor (a shr 41)) * CityHashTest.k0
            b = (b xor (b shr 41)) * CityHashTest.k0 + i.toUInt()
            expected[i] = (b shr 37).toByte()
        }

        assertContentEquals(expected, CityHashTest.generateData(size))
    }
}
