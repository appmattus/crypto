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

import kotlin.math.floor
import kotlin.math.sqrt
import kotlin.test.Test
import kotlin.test.assertEquals

class UInt128MathTest {

    @Test
    fun testPow() {
        val two = 2u.toUInt128()
        val four = 4u.toUInt128()

        for (j in 0..127) {
            assertEquals(two.pow(j), UInt128.ONE shl j)
            if (j < 64) assertEquals(four.pow(j), UInt128.ONE shl 2 * j)
        }

        for (i in 5..9) {
            for (j in 0..40) {
                assertEquals(slowPow(i.toUInt128(), j), i.toUInt128().pow(j))
            }
        }
    }

    private fun slowPow(a: UInt128, j: Int): UInt128 {
        var acu = UInt128.ONE
        for (i in 1..j) {
            acu *= a
        }
        return acu
    }

    @Test
    fun testIsqrt() {
        assertEquals("4294967295".toUInt128(), "18446744073709551615".toUInt128().isqrt())
        assertEquals("4294967296".toUInt128(), "18446744073709551616".toUInt128().isqrt())

        for (n in 0..(1 shl 53).toLong() step 997) {
            val lsqrt = floor(sqrt(n.toDouble())).toLong()
            assertEquals(lsqrt.toUInt128(), n.toUInt128().isqrt())
        }

        var num = UInt128.ONE
        var square = num * num
        while (square != UInt128.ZERO) {
            // exact value
            assertEquals(num, square.isqrt())

            // rounds down
            assertEquals(num, (square + 1u).isqrt())

            num = num shl 1
            square = num * num
        }
    }
}
