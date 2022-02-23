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

/** Represents a 128-bit unsigned integer. */
public class UInt128(
    /** The most significant word. */
    public val upper: ULong,
    /** The least significant word. */
    public val lower: ULong
) : Comparable<UInt128> {

    public companion object {

        /** A constant holding the minimum value an instance of [UInt128] can have. */
        public val MIN_VALUE: UInt128 = UInt128(0u, 0u)

        /** A constant holding the maximum value an instance of [UInt128] can have. */
        public val MAX_VALUE: UInt128 = UInt128(ULong.MAX_VALUE, ULong.MAX_VALUE)

        /** The number of bytes used to represent an instance of [UInt128] in a binary form. */
        public const val SIZE_BYTES: Int = UInt.SIZE_BYTES * 4

        /** The number of bits used to represent an instance of [UInt128] in a binary form. */
        public const val SIZE_BITS: Int = UInt.SIZE_BITS * 4

        /** The maximum radix available for conversion to and from strings. */
        public const val MAX_RADIX: Int = 36

        /** The minimum radix available for conversion to and from strings. */
        public const val MIN_RADIX: Int = 2

        /** The [UInt128] constant zero. */
        public val ZERO: UInt128 = UInt128(0u, 0u)

        /** The [UInt128] constant one. */
        public val ONE: UInt128 = UInt128(0u, 1u)
    }

    internal constructor(high: UInt, midHigh: UInt, midLow: UInt, low: UInt) : this(
        high.toULong() shl UInt.SIZE_BITS or midHigh.toULong(),
        midLow.toULong() shl UInt.SIZE_BITS or low.toULong()
    )

    internal val high: UInt = (upper shr UInt.SIZE_BITS).toUInt()
    internal val midHigh: UInt = upper.toUInt()
    internal val midLow: UInt = (lower shr UInt.SIZE_BITS).toUInt()
    internal val low: UInt = lower.toUInt()

    /**
     * Compares this value with the specified value for order.
     * Returns zero if this value is equal to the specified other value, a negative number if it's less than other,
     * or a positive number if it's greater than other.
     */
    public inline operator fun compareTo(other: UByte): Int = compareTo(other.toUInt128())

    /**
     * Compares this value with the specified value for order.
     * Returns zero if this value is equal to the specified other value, a negative number if it's less than other,
     * or a positive number if it's greater than other.
     */
    public inline operator fun compareTo(other: UShort): Int = compareTo(other.toUInt128())

    /**
     * Compares this value with the specified value for order.
     * Returns zero if this value is equal to the specified other value, a negative number if it's less than other,
     * or a positive number if it's greater than other.
     */
    public inline operator fun compareTo(other: UInt): Int = compareTo(other.toUInt128())

    /**
     * Compares this value with the specified value for order.
     * Returns zero if this value is equal to the specified other value, a negative number if it's less than other,
     * or a positive number if it's greater than other.
     */
    public inline operator fun compareTo(other: ULong): Int = compareTo(other.toUInt128())

    /**
     * Compares this value with the specified value for order.
     * Returns zero if this value is equal to the specified other value, a negative number if it's less than other,
     * or a positive number if it's greater than other.
     */
    public override fun compareTo(other: UInt128): Int = uint128Compare(this, other)

    /** Adds the [other] value to this value. */
    public inline operator fun plus(other: UByte): UInt128 = plus(other.toUInt128())

    /** Adds the [other] value to this value. */
    public inline operator fun plus(other: UShort): UInt128 = plus(other.toUInt128())

    /** Adds the [other] value to this value. */
    public inline operator fun plus(other: UInt): UInt128 = plus(other.toUInt128())

    /** Adds the [other] value to this value. */
    public inline operator fun plus(other: ULong): UInt128 = plus(other.toUInt128())

    /** Adds the [other] value to this value. */
    public operator fun plus(other: UInt128): UInt128 = uint128Plus(this, other)

    /** Subtracts the [other] value from this value. */
    public inline operator fun minus(other: UByte): UInt128 = minus(other.toUInt128())

    /** Subtracts the [other] value from this value. */
    public inline operator fun minus(other: UShort): UInt128 = minus(other.toUInt128())

    /** Subtracts the [other] value from this value. */
    public inline operator fun minus(other: UInt): UInt128 = minus(other.toUInt128())

    /** Subtracts the [other] value from this value. */
    public inline operator fun minus(other: ULong): UInt128 = minus(other.toUInt128())

    /** Subtracts the [other] value from this value. */
    public operator fun minus(other: UInt128): UInt128 = this + other.inv() + ONE

    /** Multiplies this value by the other value. */
    public inline operator fun times(other: UByte): UInt128 = times(other.toUInt128())

    /** Multiplies this value by the other value. */
    public inline operator fun times(other: UShort): UInt128 = times(other.toUInt128())

    /** Multiplies this value by the other value. */
    public inline operator fun times(other: UInt): UInt128 = times(other.toUInt128())

    /** Multiplies this value by the other value. */
    public inline operator fun times(other: ULong): UInt128 = times(other.toUInt128())

    /** Multiplies this value by the [other] value. */
    public operator fun times(other: UInt128): UInt128 = uint128Times(this, other)

    /** Divides this value by the [other] value, truncating the result to an integer that is closer to zero. */
    public inline operator fun div(other: UByte): UInt128 = div(other.toUInt128())

    /** Divides this value by the [other] value, truncating the result to an integer that is closer to zero. */
    public inline operator fun div(other: UShort): UInt128 = div(other.toUInt128())

    /** Divides this value by the [other] value, truncating the result to an integer that is closer to zero. */
    public inline operator fun div(other: UInt): UInt128 = div(other.toUInt128())

    /** Divides this value by the [other] value, truncating the result to an integer that is closer to zero. */
    public inline operator fun div(other: ULong): UInt128 = div(other.toUInt128())

    /** Divides this value by the [other] value, truncating the result to an integer that is closer to zero. */
    public operator fun div(other: UInt128): UInt128 = uint128DivMod(this, other).first

    /**
     * Calculates the remainder of truncating division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     */
    public inline operator fun rem(other: UByte): UInt128 = rem(other.toUInt128())

    /**
     * Calculates the remainder of truncating division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     */
    public inline operator fun rem(other: UShort): UInt128 = rem(other.toUInt128())

    /**
     * Calculates the remainder of truncating division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     */
    public inline operator fun rem(other: UInt): UInt128 = rem(other.toUInt128())

    /**
     * Calculates the remainder of truncating division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     */
    public inline operator fun rem(other: ULong): UInt128 = rem(other.toUInt128())

    /**
     * Calculates the remainder of truncating division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     */
    public operator fun rem(other: UInt128): UInt128 = uint128DivMod(this, other).second

    /**
     * Divides this value by the [other] value, flooring the result to an integer that is closer to negative infinity.
     *
     * For unsigned types, the results of flooring division and truncating division are the same.
     */
    public inline fun floorDiv(other: UByte): UInt128 = floorDiv(other.toUInt128())

    /**
     * Divides this value by the [other] value, flooring the result to an integer that is closer to negative infinity.
     *
     * For unsigned types, the results of flooring division and truncating division are the same.
     */
    public inline fun floorDiv(other: UShort): UInt128 = floorDiv(other.toUInt128())

    /**
     * Divides this value by the [other] value, flooring the result to an integer that is closer to negative infinity.
     *
     * For unsigned types, the results of flooring division and truncating division are the same.
     */
    public inline fun floorDiv(other: UInt): UInt128 = floorDiv(other.toUInt128())

    /**
     * Divides this value by the [other] value, flooring the result to an integer that is closer to negative infinity.
     *
     * For unsigned types, the results of flooring division and truncating division are the same.
     */
    public inline fun floorDiv(other: ULong): UInt128 = floorDiv(other.toUInt128())

    /**
     * Divides this value by the [other] value, flooring the result to an integer that is closer to negative infinity.
     *
     * For unsigned types, the results of flooring division and truncating division are the same.
     */
    public inline fun floorDiv(other: UInt128): UInt128 = div(other)

    /**
     * Calculates the remainder of flooring division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     *
     * For unsigned types, the remainders of flooring division and truncating division are the same.
     */
    public inline fun mod(other: UByte): UByte = mod(other.toUInt128()).toUByte()

    /**
     * Calculates the remainder of flooring division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     *
     * For unsigned types, the remainders of flooring division and truncating division are the same.
     */
    public inline fun mod(other: UShort): UShort = mod(other.toUInt128()).toUShort()

    /**
     * Calculates the remainder of flooring division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     *
     * For unsigned types, the remainders of flooring division and truncating division are the same.
     */
    public inline fun mod(other: UInt): UInt = mod(other.toUInt128()).toUInt()

    /**
     * Calculates the remainder of flooring division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     *
     * For unsigned types, the remainders of flooring division and truncating division are the same.
     */
    public inline fun mod(other: ULong): ULong = mod(other.toUInt128()).toULong()

    /**
     * Calculates the remainder of flooring division of this value by the [other] value.
     *
     * The result is always less than the divisor.
     *
     * For unsigned types, the remainders of flooring division and truncating division are the same.
     */
    public inline fun mod(other: UInt128): UInt128 = rem(other)

    /** Returns this value incremented by one. */
    public operator fun inc(): UInt128 = this + ONE

    /** Returns this value decremented by one. */
    public operator fun dec(): UInt128 = this - ONE

    /** Creates a range from this value to the specified [other] value. */
    public inline operator fun rangeTo(other: UInt128): UInt128Range = UInt128Range(this, other)

    /**
     * Shifts this value left by the [bitCount] number of bits.
     *
     * Note that only the seven lowest-order bits of the [bitCount] are used as the shift distance.
     * The shift distance actually used is therefore always in the range `0..127`.
     */
    public infix fun shl(bitCount: Int): UInt128 = uint128Shl(this, bitCount)

    /**
     * Shifts this value right by the [bitCount] number of bits, filling the leftmost bits with zeros.
     *
     * Note that only the seven lowest-order bits of the [bitCount] are used as the shift distance.
     * The shift distance actually used is therefore always in the range `0..127`.
     */
    public infix fun shr(bitCount: Int): UInt128 = uint128Shr(this, bitCount)

    /** Performs a bitwise AND operation between the two values. */
    public infix fun and(other: UInt128): UInt128 = UInt128(upper and other.upper, lower and other.lower)

    /** Performs a bitwise OR operation between the two values. */
    public infix fun or(other: UInt128): UInt128 = UInt128(upper or other.upper, lower or other.lower)

    /** Performs a bitwise XOR operation between the two values. */
    public infix fun xor(other: UInt128): UInt128 = UInt128(upper xor other.upper, lower xor other.lower)

    /** Inverts the bits in this value. */
    public fun inv(): UInt128 = UInt128(upper.inv(), lower.inv())

    /** Returns this value. */
    public operator fun unaryPlus(): UInt128 = this

    /** Returns the negative of this value. */
    public operator fun unaryMinus(): UInt128 = inv() + ONE

    /**
     * Converts this [UInt128] value to [Byte].
     *
     * If this value is less than or equal to [Byte.MAX_VALUE], the resulting [Byte] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [Byte] value is represented by the least significant 8 bits of this [UInt128] value.
     * Note that the resulting [Byte] value may be negative.
     */
    public inline fun toByte(): Byte = lower.toByte()

    /**
     * Converts this [UInt128] value to [Short].
     *
     * If this value is less than or equal to [Short.MAX_VALUE], the resulting [Short] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [Short] value is represented by the least significant 16 bits of this [UInt128] value.
     * Note that the resulting [Short] value may be negative.
     */
    public inline fun toShort(): Short = lower.toShort()

    /**
     * Converts this [UInt128] value to [Int].
     *
     * If this value is less than or equal to [Int.MAX_VALUE], the resulting [Int] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [Int] value is represented by the least significant 32 bits of this [UInt128] value.
     * Note that the resulting [Int] value may be negative.
     */
    public inline fun toInt(): Int = lower.toInt()

    /**
     * Converts this [UInt128] value to [Long].
     *
     * If this value is less than or equal to [Long.MAX_VALUE], the resulting [Long] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [Long] value is represented by the least significant 64 bits of this [UInt128] value.
     * Note that the resulting [Long] value may be negative.
     */
    public inline fun toLong(): Long = lower.toLong()

    /**
     * Converts this [UInt128] value to [UByte].
     *
     * If this value is less than or equal to [UByte.MAX_VALUE], the resulting [UByte] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [UByte] value is represented by the least significant 8 bits of this [UInt128] value.
     */
    public inline fun toUByte(): UByte = lower.toUByte()

    /**
     * Converts this [UInt128] value to [UShort].
     *
     * If this value is less than or equal to [UShort.MAX_VALUE], the resulting [UShort] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [UShort] value is represented by the least significant 16 bits of this [UInt128] value.
     */
    public inline fun toUShort(): UShort = lower.toUShort()

    /**
     * Converts this [UInt128] value to [UInt].
     *
     * If this value is less than or equal to [UInt.MAX_VALUE], the resulting [UInt] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [UInt] value is represented by the least significant 32 bits of this [UInt128] value.
     */
    public inline fun toUInt(): UInt = lower.toUInt()

    /**
     * Converts this [UInt128] value to [ULong].
     *
     * If this value is less than or equal to [ULong.MAX_VALUE], the resulting [ULong] value represents
     * the same numerical value as this [UInt128].
     *
     * The resulting [ULong] value is represented by the least significant 64 bits of this [UInt128] value.
     */
    public inline fun toULong(): ULong = lower

    /** Returns this value. */
    public inline fun toUInt128(): UInt128 = this

    override fun equals(other: Any?): Boolean {
        // Note that this needs to be consistent with compareTo
        if (this === other) {
            return true
        }
        if (other is UInt128) {
            return upper == other.upper && lower == other.lower
        }
        return false
    }

    override fun hashCode(): Int = (high * 31u + midHigh * 23u + midLow * 13u + low).toInt()

    override fun toString(): String = toString(10)
}

/**
 * Converts this [UByte] value to [UInt128].
 *
 * The resulting [UInt128] value represents the same numerical value as this [UByte].
 *
 * The least significant 8 bits of the resulting [UInt128] value are the same as the bits of this [UByte] value,
 * whereas the most significant 120 bits are filled with zeros.
 */
public inline fun UByte.toUInt128(): UInt128 = UInt128(0uL, toULong())

/**
 * Converts this [UShort] value to [UInt128].
 *
 * The resulting [UInt128] value represents the same numerical value as this [UShort].
 *
 * The least significant 16 bits of the resulting [UInt128] value are the same as the bits of this [UShort] value,
 * whereas the most significant 112 bits are filled with zeros.
 */
public inline fun UShort.toUInt128(): UInt128 = UInt128(0uL, toULong())

/**
 * Converts this [UInt] value to [UInt128].
 *
 * The resulting [UInt128] value represents the same numerical value as this [UInt].
 *
 * The least significant 32 bits of the resulting [UInt128] value are the same as the bits of this [UInt] value,
 * whereas the most significant 96 bits are filled with zeros.
 */
public inline fun UInt.toUInt128(): UInt128 = UInt128(0uL, toULong())

/**
 * Converts this [ULong] value to [UInt128].
 *
 * The resulting [UInt128] value represents the same numerical value as this [ULong].
 *
 * The least significant 64 bits of the resulting [UInt128] value are the same as the bits of this [ULong] value,
 * whereas the most significant 64 bits are filled with zeros.
 */
public inline fun ULong.toUInt128(): UInt128 = UInt128(0uL, this)

/**
 * Converts this [Byte] value to [UInt128].
 *
 * If this value is positive, the resulting [UInt128] value represents the same numerical value as this [Byte].
 *
 * The least significant 8 bits of the resulting [UInt128] value are the same as the bits of this [Byte] value,
 * whereas the most significant 120 bits are filled with the sign bit of this value.
 */
public inline fun Byte.toUInt128(): UInt128 = UInt128(if (this < 0) ULong.MAX_VALUE else 0uL, toULong())

/**
 * Converts this [Short] value to [UInt128].
 *
 * If this value is positive, the resulting [UInt128] value represents the same numerical value as this [Short].
 *
 * The least significant 16 bits of the resulting [UInt128] value are the same as the bits of this [Short] value,
 * whereas the most significant 112 bits are filled with the sign bit of this value.
 */
public inline fun Short.toUInt128(): UInt128 = UInt128(if (this < 0) ULong.MAX_VALUE else 0uL, toULong())

/**
 * Converts this [Int] value to [UInt128].
 *
 * If this value is positive, the resulting [UInt128] value represents the same numerical value as this [Int].
 *
 * The least significant 32 bits of the resulting [UInt128] value are the same as the bits of this [Int] value,
 * whereas the most significant 96 bits are filled with the sign bit of this value.
 */
public inline fun Int.toUInt128(): UInt128 = UInt128(if (this < 0) ULong.MAX_VALUE else 0uL, toULong())

/**
 * Converts this [Long] value to [UInt128].
 *
 * If this value is positive, the resulting [UInt128] value represents the same numerical value as this [Long].
 *
 * The least significant 64 bits of the resulting [UInt128] value are the same as the bits of this [Long] value,
 * whereas the most significant 64 bits are filled with the sign bit of this value.
 */
public inline fun Long.toUInt128(): UInt128 = UInt128(if (this < 0) ULong.MAX_VALUE else 0uL, toULong())
