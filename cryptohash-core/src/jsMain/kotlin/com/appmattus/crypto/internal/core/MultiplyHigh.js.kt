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

import com.appmattus.crypto.InternalCryptohash

/**
 * Kotlin/JS stores a [Long] as an object holding two 32-bit halves, so every [Long] operation allocates a new one, and
 * [multiplyHighPortable] makes dozens of them. Engines without a JIT to optimise those allocations away, such as
 * Hermes, are particularly slow at it.
 *
 * This multiplies 16-bit limbs as [Int]s instead, which compile to plain JS numbers, so the only [Long]s it makes are
 * from splitting the arguments and joining the result.
 */
@Suppress("MagicNumber", "LongMethod")
@InternalCryptohash
public actual fun multiplyHigh(a: ULong, b: ULong): ULong {
    val aLow = a.toInt()
    val aHigh = (a shr 32).toInt()
    val bLow = b.toInt()
    val bHigh = (b shr 32).toInt()

    val a0 = aLow and 0xffff
    val a1 = aLow ushr 16
    val a2 = aHigh and 0xffff
    val a3 = aHigh ushr 16
    val b0 = bLow and 0xffff
    val b1 = bLow ushr 16
    val b2 = bHigh and 0xffff
    val b3 = bHigh ushr 16

    // Each product is below 2^32, so its Int bits are exact when read as unsigned
    val p00 = a0 * b0
    val p01 = a0 * b1
    val p02 = a0 * b2
    val p03 = a0 * b3
    val p10 = a1 * b0
    val p11 = a1 * b1
    val p12 = a1 * b2
    val p13 = a1 * b3
    val p20 = a2 * b0
    val p21 = a2 * b1
    val p22 = a2 * b2
    val p23 = a2 * b3
    val p30 = a3 * b0
    val p31 = a3 * b1
    val p32 = a3 * b2
    val p33 = a3 * b3

    // Column k of the 128-bit product sums the 16-bit halves landing at bit 16k, plus the carry from column k - 1.
    // Every column stays far below 2^31.
    var c = (p00 ushr 16) + (p01 and 0xffff) + (p10 and 0xffff)
    c = (c ushr 16) + (p01 ushr 16) + (p10 ushr 16) +
        (p02 and 0xffff) + (p11 and 0xffff) + (p20 and 0xffff)
    c = (c ushr 16) + (p02 ushr 16) + (p11 ushr 16) + (p20 ushr 16) +
        (p03 and 0xffff) + (p12 and 0xffff) + (p21 and 0xffff) + (p30 and 0xffff)
    c = (c ushr 16) + (p03 ushr 16) + (p12 ushr 16) + (p21 ushr 16) + (p30 ushr 16) +
        (p13 and 0xffff) + (p22 and 0xffff) + (p31 and 0xffff)
    val d4 = c and 0xffff
    c = (c ushr 16) + (p13 ushr 16) + (p22 ushr 16) + (p31 ushr 16) +
        (p23 and 0xffff) + (p32 and 0xffff)
    val d5 = c and 0xffff
    c = (c ushr 16) + (p23 ushr 16) + (p32 ushr 16) + (p33 and 0xffff)
    val d6 = c and 0xffff
    c = (c ushr 16) + (p33 ushr 16)
    val d7 = c and 0xffff

    val high = (d7 shl 16) or d6
    val low = (d5 shl 16) or d4
    return (high.toULong() shl 32) or (low.toUInt().toULong())
}
