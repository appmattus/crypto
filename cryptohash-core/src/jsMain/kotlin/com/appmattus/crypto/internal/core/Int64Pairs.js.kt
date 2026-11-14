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

/*
 * Helpers for 64-bit arithmetic on Kotlin/JS with each value held as a pair of Ints, high and low. Kotlin/JS stores a
 * Long as an object and allocates one on nearly every operation; Ints compile to plain JS numbers.
 */

/** The high half of the last [mul64] result. JS is single-threaded, so one shared copy is safe. */
@InternalCryptohash
public var mul64High: Int = 0
    private set

/**
 * The low 64 bits of the product of (ah, al) and (bh, bl): returns the low half and leaves the high half in
 * [mul64High]
 */
@Suppress("MagicNumber")
@InternalCryptohash
public fun mul64(ah: Int, al: Int, bh: Int, bl: Int): Int {
    // The full 64-bit product of the low halves, from 16-bit pieces, each product exact when read as unsigned
    val a0 = al and 0xffff
    val a1 = al ushr 16
    val b0 = bl and 0xffff
    val b1 = bl ushr 16
    val p00 = a0 * b0
    val p01 = a0 * b1
    val p10 = a1 * b0
    val mid = (p00 ushr 16) + (p01 and 0xffff) + (p10 and 0xffff)
    val lowHigh = a1 * b1 + (p01 ushr 16) + (p10 ushr 16) + (mid ushr 16)
    // The cross terms only affect the high half
    mul64High = lowHigh + ah * bl + al * bh
    return al * bl
}

/** The carry out of the low half of an addition, given the [sum] and one of its [operand]s */
@Suppress("NOTHING_TO_INLINE")
@InternalCryptohash
public inline fun carry(sum: Int, operand: Int): Int =
    if ((sum xor Int.MIN_VALUE) < (operand xor Int.MIN_VALUE)) 1 else 0

@Suppress("NOTHING_TO_INLINE", "MagicNumber")
@InternalCryptohash
public inline fun readIntLe(data: ByteArray, offset: Int): Int =
    (data[offset].toInt() and 0xff) or
        ((data[offset + 1].toInt() and 0xff) shl 8) or
        ((data[offset + 2].toInt() and 0xff) shl 16) or
        (data[offset + 3].toInt() shl 24)

@Suppress("MagicNumber")
@InternalCryptohash
public fun longOf(high: Int, low: Int): Long = (high.toLong() shl 32) or (low.toLong() and 0xffffffffL)

@Suppress("MagicNumber")
@InternalCryptohash
public fun highOf(value: Long): Int = (value ushr 32).toInt()
