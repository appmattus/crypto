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

package com.appmattus.crypto.internal.core

import com.appmattus.uint.toUInt128
import kotlin.random.Random
import kotlin.random.nextULong
import kotlin.test.Test
import kotlin.test.assertEquals

class MultiplyHighTest {

    private val edges = listOf(
        0uL, 1uL, 2uL, 0xffffffffuL, 0x100000000uL, 0x7fffffffffffffffuL, 0x8000000000000000uL, ULong.MAX_VALUE
    )

    @Test
    fun edgeCases() {
        for (a in edges) {
            for (b in edges) {
                check(a, b)
            }
        }
    }

    @Test
    fun randomValues() {
        val random = Random(0)
        repeat(10_000) {
            check(random.nextULong(), random.nextULong())
        }
    }

    private fun check(a: ULong, b: ULong) {
        // UInt128 multiplies independently of this code, so it's the reference
        val expected = (a.toUInt128() * b).upper
        assertEquals(expected, multiplyHigh(a, b), "multiplyHigh($a, $b)")
        assertEquals(expected, multiplyHighPortable(a, b), "multiplyHighPortable($a, $b)")
    }
}
