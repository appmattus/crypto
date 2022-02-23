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
 * A range of values of type [UInt128].
 */
public class UInt128Range(start: UInt128, endInclusive: UInt128) : UInt128Progression(start, endInclusive, 1), ClosedRange<UInt128> {
    override val start: UInt128 get() = first
    override val endInclusive: UInt128 get() = last

    @Suppress("ConvertTwoComparisonsToRangeCheck")
    override fun contains(value: UInt128): Boolean = first <= value && value <= last

    /**
     * Checks if the range is empty.

     * The range is empty if its start value is greater than the end value.
     */
    override fun isEmpty(): Boolean = first > last

    override fun equals(other: Any?): Boolean =
        other is UInt128Range && (isEmpty() && other.isEmpty() ||
                first == other.first && last == other.last)

    override fun hashCode(): Int =
        if (isEmpty()) -1 else (31 * (first xor (first shr 32)).toInt() + (last xor (last shr 32)).toInt())

    override fun toString(): String = "$first..$last"

    public companion object {
        /** An empty range of values of type [UInt128]. */
        public val EMPTY: UInt128Range = UInt128Range(UInt128.MAX_VALUE, UInt128.MIN_VALUE)
    }
}

/**
 * A progression of values of type [UInt128].
 */
public open class UInt128Progression internal constructor(
    start: UInt128,
    endInclusive: UInt128,
    step: Long
) : Iterable<UInt128> {
    init {
        if (step == 0L) throw IllegalArgumentException("Step must be non-zero.")
        if (step == Long.MIN_VALUE) throw IllegalArgumentException("Step must be greater than Long.MIN_VALUE to avoid overflow on negation.")
    }

    /**
     * The first element in the progression.
     */
    public val first: UInt128 = start

    /**
     * The last element in the progression.
     */
    public val last: UInt128 = getProgressionLastElement(start, endInclusive, step)

    /**
     * The step of the progression.
     */
    @Suppress("CanBePrimaryConstructorProperty")
    public val step: Long = step

    final override fun iterator(): Iterator<UInt128> = UInt128ProgressionIterator(first, last, step)

    /**
     * Checks if the progression is empty.

     * Progression with a positive step is empty if its first element is greater than the last element.
     * Progression with a negative step is empty if its first element is less than the last element.
     */
    public open fun isEmpty(): Boolean = if (step > 0) first > last else first < last

    override fun equals(other: Any?): Boolean =
        other is UInt128Progression && (isEmpty() && other.isEmpty() ||
                first == other.first && last == other.last && step == other.step)

    override fun hashCode(): Int = if (isEmpty()) {
        -1
    } else {
        (31 * (31 * (first xor (first shr 32)).toInt() + (last xor (last shr 32)).toInt()) + (step xor (step ushr 32)).toInt())
    }

    override fun toString(): String = if (step > 0) "$first..$last step $step" else "$first downTo $last step ${-step}"

    public companion object {
        /**
         * Creates UInt128Progression within the specified bounds of a closed range.

         * The progression starts with the [rangeStart] value and goes toward the [rangeEnd] value not excluding it, with the specified [step].
         * In order to go backwards the [step] must be negative.
         *
         * [step] must be greater than `Long.MIN_VALUE` and not equal to zero.
         */
        public fun fromClosedRange(rangeStart: UInt128, rangeEnd: UInt128, step: Long): UInt128Progression =
            UInt128Progression(rangeStart, rangeEnd, step)
    }
}

/**
 * An iterator over a progression of values of type [UInt128].
 * @property step the number by which the value is incremented on each step.
 */
@SinceKotlin("1.3")
@Suppress("DEPRECATION_ERROR")
private class UInt128ProgressionIterator(first: UInt128, last: UInt128, step: Long) : UInt128Iterator() {
    private val finalElement = last
    private var hasNext: Boolean = if (step > 0) first <= last else first >= last
    private val step = step.toULong() // use 2-complement math for negative steps
    private var next = if (hasNext) first else finalElement

    override fun hasNext(): Boolean = hasNext

    override fun nextUInt128(): UInt128 {
        val value = next
        if (value == finalElement) {
            if (!hasNext) throw NoSuchElementException()
            hasNext = false
        } else {
            next += step
        }
        return value
    }
}

/**
 * Returns a range from this value up to but excluding the specified [to] value.
 *
 * If the [to] value is less than or equal to `this` value, then the returned range is empty.
 */
public infix fun UInt128.until(to: UInt128): UInt128Range {
    if (to <= UInt128.MIN_VALUE) return UInt128Range.EMPTY
    return this..(to - 1u)
}

/**
 * Returns a progression that goes over the same range with the given step.
 */
public infix fun UInt128Progression.step(step: Long): UInt128Progression {
    if (step <= 0) throw IllegalArgumentException("Step must be positive, was: $step.")
    return UInt128Progression.fromClosedRange(first, last, if (this.step > 0) step else -step)
}

/**
 * Calculates the final element of a bounded arithmetic progression, i.e. the last element of the progression which is in the range
 * from [start] to [end] in case of a positive [step], or from [end] to [start] in case of a negative
 * [step].
 *
 * No validation on passed parameters is performed. The given parameters should satisfy the condition:
 *
 * - either `step > 0` and `start <= end`,
 * - or `step < 0` and `start >= end`.
 *
 * @param start first element of the progression
 * @param end ending bound for the progression
 * @param step increment, or difference of successive elements in the progression
 * @return the final element of the progression
 * @suppress
 */
@PublishedApi
@SinceKotlin("1.3")
internal fun getProgressionLastElement(start: UInt128, end: UInt128, step: Long): UInt128 = when {
    step > 0 -> if (start >= end) end else end - differenceModulo(end, start, step.toUInt128())
    step < 0 -> if (start <= end) end else end + differenceModulo(start, end, (-step).toUInt128())
    else -> throw IllegalArgumentException("Step is zero.")
}

private fun differenceModulo(a: UInt128, b: UInt128, c: UInt128): UInt128 {
    val ac = a % c
    val bc = b % c
    return if (ac >= bc) ac - bc else ac - bc + c
}
