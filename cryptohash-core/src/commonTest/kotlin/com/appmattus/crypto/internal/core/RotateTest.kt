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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.rotateLeft as stdlibRotateLeft
import kotlin.rotateRight as stdlibRotateRight

/**
 * The inline rotates must match the standard library's for every bit count, including those outside 0 until 32
 */
class RotateTest {

    private val values = listOf(0, 1, -1, 0x12345678, Int.MIN_VALUE, Int.MAX_VALUE, 0x5bd1e995)

    @Test
    fun intRotatesMatchTheStandardLibrary() {
        for (value in values) {
            for (bitCount in -33..65) {
                assertEquals(value.stdlibRotateLeft(bitCount), value.rotateLeft(bitCount), "rotateLeft $value by $bitCount")
                assertEquals(value.stdlibRotateRight(bitCount), value.rotateRight(bitCount), "rotateRight $value by $bitCount")
            }
        }
    }

    @Test
    fun uintRotatesMatchTheStandardLibrary() {
        for (value in values.map { it.toUInt() }) {
            for (bitCount in -33..65) {
                assertEquals(value.stdlibRotateLeft(bitCount), value.rotateLeft(bitCount), "rotateLeft $value by $bitCount")
                assertEquals(value.stdlibRotateRight(bitCount), value.rotateRight(bitCount), "rotateRight $value by $bitCount")
            }
        }
    }
}
