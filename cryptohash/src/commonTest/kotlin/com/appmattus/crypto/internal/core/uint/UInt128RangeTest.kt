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
import com.appmattus.crypto.internal.core.uint.UInt128.Companion.ZERO
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UInt128RangeTest {

    @Test
    fun testRangeTo() {
        val range1 = ZERO..MAX_VALUE
        assertTrue(range1.contains(ZERO))
        assertTrue(range1.contains(UInt128(1u, 0u)))
        assertTrue(range1.contains(MAX_VALUE))

        val range2 = UInt128(0u, ULong.MAX_VALUE)..UInt128(1u, 0u)
        assertFalse(range2.contains(UInt128(0u, ULong.MAX_VALUE - 1u)))
        assertTrue(range2.contains(UInt128(0u, ULong.MAX_VALUE)))
        assertTrue(range2.contains(UInt128(1u, 0u)))
        assertFalse(range2.contains(UInt128(1u, 1u)))
    }

    @Test
    fun testUntil() {
        val range1 = ZERO until MAX_VALUE
        assertTrue(range1.contains(ZERO))
        assertTrue(range1.contains(UInt128(1u, 0u)))
        assertTrue(range1.contains(MAX_VALUE - 1u))
        assertFalse(range1.contains(MAX_VALUE))

        val range2 = UInt128(0u, ULong.MAX_VALUE) until UInt128(1u, 0u)
        assertFalse(range2.contains(UInt128(0u, ULong.MAX_VALUE - 1u)))
        assertTrue(range2.contains(UInt128(0u, ULong.MAX_VALUE)))
        assertFalse(range2.contains(UInt128(1u, 0u)))
        assertFalse(range2.contains(UInt128(1u, 1u)))
    }
}
