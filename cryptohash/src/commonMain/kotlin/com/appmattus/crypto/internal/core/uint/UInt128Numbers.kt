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
 * Counts the number of set bits in the binary representation of this [UInt128] number.
 */
public inline fun UInt128.countOneBits(): Int = upper.countOneBits() + lower.countOneBits()

/**
 * Counts the number of consecutive most significant bits that are zero in the binary representation of this [UInt128] number.
 */
public inline fun UInt128.countLeadingZeroBits(): Int =
    if (upper == 0uL) ULong.SIZE_BITS + lower.countLeadingZeroBits() else upper.countLeadingZeroBits()

/**
 * Counts the number of consecutive least significant bits that are zero in the binary representation of this [UInt128] number.
 */
public inline fun UInt128.countTrailingZeroBits(): Int =
    if (lower == 0uL) ULong.SIZE_BITS + upper.countTrailingZeroBits() else lower.countTrailingZeroBits()

/**
 * Returns a number having a single bit set in the position of the most significant set bit of this [UInt128] number,
 * or zero, if this number is zero.
 */
public inline fun UInt128.takeHighestOneBit(): UInt128 =
    if (upper == 0uL) UInt128(0u, lower.takeHighestOneBit()) else UInt128(upper.takeHighestOneBit(), 0u)

/**
 * Returns a number having a single bit set in the position of the least significant set bit of this [UInt128] number,
 * or zero, if this number is zero.
 */
public inline fun UInt128.takeLowestOneBit(): UInt128 =
    if (lower == 0uL) UInt128(upper.takeLowestOneBit(), 0u) else UInt128(0u, lower.takeLowestOneBit())

/**
 * Rotates the binary representation of this [UInt128] number left by the specified [bitCount] number of bits.
 * The most significant bits pushed out from the left side reenter the number as the least significant bits on the right side.
 *
 * Rotating the number left by a negative bit count is the same as rotating it right by the negated bit count:
 * `number.rotateLeft(-n) == number.rotateRight(n)`
 *
 * Rotating by a multiple of [UInt128.SIZE_BITS] (128) returns the same number, or more generally
 * `number.rotateLeft(n) == number.rotateLeft(n % 128)`
 */
public inline fun UInt128.rotateLeft(bitCount: Int): UInt128 =
    (this shl (bitCount and 127)) or (this shr 128 - (bitCount and 127))

/**
 * Rotates the binary representation of this [UInt128] number right by the specified [bitCount] number of bits.
 * The least significant bits pushed out from the right side reenter the number as the most significant bits on the left side.
 *
 * Rotating the number right by a negative bit count is the same as rotating it left by the negated bit count:
 * `number.rotateRight(-n) == number.rotateLeft(n)`
 *
 * Rotating by a multiple of [UInt128.SIZE_BITS] (128) returns the same number, or more generally
 * `number.rotateRight(n) == number.rotateRight(n % 128)`
 */
public inline fun UInt128.rotateRight(bitCount: Int): UInt128 =
    (this shr (bitCount and 127)) or (this shl 128 - (bitCount and 127))
