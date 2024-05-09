/*
 * Copyright 2022-2024 Appmattus Limited
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

internal fun uint128Compare(v1: UInt128, v2: UInt128): Int {
    val cmp = v1.upper.compareTo(v2.upper)
    if (cmp == 0) {
        return v1.lower.compareTo(v2.lower)
    }
    return cmp
}

internal fun uint128Plus(v1: UInt128, v2: UInt128): UInt128 {
    val partial0 = v1.low.toULong() + v2.low.toULong()
    val partial1 = v1.midLow.toULong() + v2.midLow.toULong() + (partial0 shr UInt.SIZE_BITS)
    val partial2 = v1.midHigh.toULong() + v2.midHigh.toULong() + (partial1 shr UInt.SIZE_BITS)
    val partial3 = v1.high.toULong() + v2.high.toULong() + (partial2 shr UInt.SIZE_BITS)
    return UInt128(partial3.toUInt(), partial2.toUInt(), partial1.toUInt(), partial0.toUInt())
}

internal fun uint128Times(v1: UInt128, v2: UInt128): UInt128 {
    // multiply each component of the values
    val ll = v1.low.toULong() * v2.low.toULong()
    val mll = v1.midLow.toULong() * v2.low.toULong()
    val mhl = v1.midHigh.toULong() * v2.low.toULong()
    val hl = v1.high.toULong() * v2.low.toULong()
    val lml = v1.low.toULong() * v2.midLow.toULong()
    val mlml = v1.midLow.toULong() * v2.midLow.toULong()
    val mhml = v1.midHigh.toULong() * v2.midLow.toULong()
    val lmh = v1.low.toULong() * v2.midHigh.toULong()
    val mlmh = v1.midLow.toULong() * v2.midHigh.toULong()
    val lh = v1.low.toULong() * v2.high.toULong()

    // first row
    val fourth32: ULong = ll and 0xffffffffu
    var third32: ULong = (lml and 0xffffffffu) + (ll shr 32)
    var second32: ULong = (lmh and 0xffffffffu) + (lml shr 32)
    var first32: ULong = (lh and 0xffffffffu) + (lmh shr 32)

    // second row
    third32 += (mll and 0xffffffffu)
    second32 += (mlml and 0xffffffffu) + (mll shr 32)
    first32 += (mlmh and 0xffffffffu) + (mlml shr 32)

    // third row
    second32 += (mhl and 0xffffffffu)
    first32 += (mhml and 0xffffffffu) + (mhl shr 32)

    // fourth row
    first32 += (hl and 0xffffffffu)

    // move carry to next digit
    third32 += fourth32 shr 32
    second32 += third32 shr 32
    first32 += second32 shr 32

    // remove carry from current digit
    return UInt128(first32.toUInt(), second32.toUInt(), third32.toUInt(), fourth32.toUInt())
}

@Suppress("ReturnCount")
internal fun uint128DivMod(dividend: UInt128, divisor: UInt128): Pair<UInt128, UInt128> {
    if (divisor == UInt128.ZERO) {
        error("Error: division or modulus by 0")
    } else if (divisor == UInt128.ONE) {
        return Pair(dividend, UInt128.ZERO)
    } else if (dividend == divisor) {
        return Pair(UInt128.ONE, UInt128.ZERO)
    } else if ((dividend == UInt128.ZERO) || (dividend < divisor)) {
        return Pair(UInt128.ZERO, dividend)
    }

    var qrFirst = UInt128.ZERO
    var qrSecond = UInt128.ZERO
    for (x in (UInt128.SIZE_BITS - dividend.countLeadingZeroBits()) downTo 1) {
        qrFirst = qrFirst shl 1
        qrSecond = qrSecond shl 1

        if ((dividend shr (x - 1)) and UInt128.ONE != UInt128.ZERO) {
            ++qrSecond
        }

        if (qrSecond >= divisor) {
            qrSecond -= divisor
            ++qrFirst
        }
    }

    return Pair(qrFirst, qrSecond)
}

@Suppress("ReturnCount")
internal fun uint128Shl(v: UInt128, n: Int): UInt128 {
    if (n == 0) {
        return v
    } else if (n >= UInt128.SIZE_BITS || n <= -UInt128.SIZE_BITS) {
        return UInt128.ZERO // All bits are gone
    } else if (n < 0) {
        return v shr -n // -ve left shift is right shift
    }
    var h = if (n >= ULong.SIZE_BITS) v.lower else v.upper
    var l = if (n >= ULong.SIZE_BITS) 0uL else v.lower
    val r: Int = n % ULong.SIZE_BITS
    if (r > 0) {
        val c = l shr (ULong.SIZE_BITS - r)
        h = (h shl r) + c
        l = l shl r
    }
    return UInt128(h, l)
}

@Suppress("ReturnCount")
internal fun uint128Shr(v: UInt128, n: Int): UInt128 {
    if (n == 0) {
        return v
    } else if (n >= UInt128.SIZE_BITS || n <= -UInt128.SIZE_BITS) {
        return UInt128.ZERO // All bits are gone
    } else if (n < 0) {
        return v shl -n // -ve right shift is left shift
    }
    var h = if (n >= ULong.SIZE_BITS) 0uL else v.upper
    var l = if (n >= ULong.SIZE_BITS) v.upper else v.lower
    val r: Int = n % ULong.SIZE_BITS
    if (r > 0) {
        val c = h shl ULong.SIZE_BITS - r
        h = h shr r
        l = l shr r or c
    }
    return UInt128(h, l)
}
