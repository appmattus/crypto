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

/**
 * Returns a string representation of this [UInt128] value in the specified [radix].
 *
 * @throws IllegalArgumentException when [radix] is not a valid radix for number to string conversion.
 */
public fun UInt128.toString(radix: Int): String {
    val chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    if (radix < UInt128.MIN_RADIX || radix > UInt128.MAX_RADIX) {
        throw IllegalArgumentException("Illegal radix: $radix")
    }

    if (this == UInt128.ZERO) {
        return "0"
    }

    val out = StringBuilder()
    var qr = Pair(this, UInt128.ZERO)
    do {
        qr = uint128DivMod(qr.first, radix.toUInt128())
        out.append(chars[qr.second.toInt()])
    } while (qr.first != UInt128.ZERO)

    return out.reverse().toString()
}

/**
 * Parses the string as a [UInt128] number and returns the result.
 * @throws NumberFormatException if the string is not a valid representation of a number.
 */
public fun String.toUInt128(): UInt128 = toUInt128OrNull() ?: throw NumberFormatException("Invalid number format: '$this'")

/**
 * Parses the string as a [UInt128] number and returns the result.
 * @throws NumberFormatException if the string is not a valid representation of a number.
 * @throws IllegalArgumentException when [radix] is not a valid radix for string to number conversion.
 */
public fun String.toUInt128(radix: Int): UInt128 = toUInt128OrNull(radix) ?: throw NumberFormatException("Invalid number format: '$this'")

/**
 * Parses the string as an [ULong] number and returns the result
 * or `null` if the string is not a valid representation of a number.
 */
public inline fun String.toUInt128OrNull(): UInt128? = toUInt128OrNull(radix = 10)

/**
 * Parses the string as an [ULong] number and returns the result
 * or `null` if the string is not a valid representation of a number.
 *
 * @throws IllegalArgumentException when [radix] is not a valid radix for string to number conversion.
 */
public fun String.toUInt128OrNull(radix: Int): UInt128? {
    val chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    if (radix < UInt128.MIN_RADIX || radix > UInt128.MAX_RADIX) {
        throw IllegalArgumentException("Illegal radix: $radix")
    }

    if (this.isEmpty()) return null

    val limit: UInt128 = UInt128.MAX_VALUE
    val start: Int

    val firstChar = this[0]
    if (firstChar < '0') {
        if (this.length == 1 || firstChar != '+') return null
        start = 1
    } else {
        start = 0
    }

    val limitForMaxRadix = limit / UInt128.MAX_RADIX.toUInt128() //  9452287970026068429538183539771339207  //  limit / 36

    var limitBeforeMul = limitForMaxRadix
    val uradix = radix.toUInt128()
    var result = UInt128.ZERO
    for (i in start until this.length) {
        val digit = chars.indexOf(this[i])
        if (digit < 0 || digit >= radix) return null
        if (result > limitBeforeMul) {
            if (limitBeforeMul == limitForMaxRadix) {
                limitBeforeMul = limit / uradix

                if (result > limitBeforeMul) {
                    return null
                }
            } else {
                return null
            }
        }

        result *= uradix

        val beforeAdding = result
        result += digit.toUInt128()
        if (result < beforeAdding) return null // overflow has happened
    }

    return result
}
