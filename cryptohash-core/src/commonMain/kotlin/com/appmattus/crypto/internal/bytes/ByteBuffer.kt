/*
 * Copyright 2022-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.bytes

import com.appmattus.crypto.InternalCryptohash
import com.appmattus.crypto.internal.core.copyBytes
import com.appmattus.crypto.internal.core.decodeBEInt
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.decodeLELong

/**
 * Bytes added to a single growable array, of which the first [size] are the contents, so [get] is constant time
 * however many arrays were added.
 *
 * [get] and the word decoders are inline, so a hash's inner loop reads [bytes] directly. Kotlin/Native can then keep
 * the array in a register across a loop's reads, instead of making a call per word. Every read is still checked
 * against [size], which is smaller than the array when it has spare capacity.
 */
@Suppress("NOTHING_TO_INLINE", "TooManyFunctions")
@InternalCryptohash
public class ByteBuffer private constructor(bytes: ByteArray, size: Int) : Iterable<Byte> {

    public constructor() : this(ByteArray(0), 0)

    /**
     * The backing array, of which the first [size] bytes are the contents. Public only so the inline accessors, and
     * hashes' JS fast paths in other modules, can read it, as inline functions can't reach private members. Never
     * write to it.
     */
    public var bytes: ByteArray = bytes
        private set

    public var size: Int = size
        private set

    public fun add(value: ByteArray, offset: Int = 0, length: Int = value.size) {
        if (length > 0) {
            if (size + length > bytes.size) {
                bytes = bytes.copyOf(maxOf(size + length, bytes.size * 2, MIN_CAPACITY))
            }
            copyBytes(value, offset, bytes, size, length)
            size += length
        }
    }

    /** Appends a single byte, without the array that [add] of a [ByteArray] would need */
    public fun add(value: Byte) {
        if (size == bytes.size) {
            bytes = bytes.copyOf(maxOf(bytes.size * 2, MIN_CAPACITY))
        }
        bytes[size++] = value
    }

    public fun copyOf(): ByteBuffer = ByteBuffer(bytes.copyOf(size), size)

    /**
     * Returns the byte at [index]. This method can be called using the index operator.
     *
     * @throws IndexOutOfBoundsException if [index] isn't within [size]
     */
    public inline operator fun get(index: Int): Byte {
        checkRange(index, 1, size)
        return bytes[index]
    }

    /**
     * Decodes the 32-bit little-endian integer at [off].
     *
     * @throws IndexOutOfBoundsException if the four bytes aren't all within [size]
     */
    public inline fun decodeLEInt(off: Int): Int {
        checkRange(off, Int.SIZE_BYTES, size)
        return decodeLEInt(bytes, off)
    }

    /**
     * Decodes the 32-bit little-endian unsigned integer at [off].
     *
     * @throws IndexOutOfBoundsException if the four bytes aren't all within [size]
     */
    public inline fun decodeLEUInt(off: Int): UInt = decodeLEInt(off).toUInt()

    /**
     * Decodes the 32-bit big-endian integer at [off].
     *
     * @throws IndexOutOfBoundsException if the four bytes aren't all within [size]
     */
    public inline fun decodeBEInt(off: Int): Int {
        checkRange(off, Int.SIZE_BYTES, size)
        return decodeBEInt(bytes, off)
    }

    /**
     * Decodes the 64-bit little-endian integer at [off].
     *
     * @throws IndexOutOfBoundsException if the eight bytes aren't all within [size]
     */
    public inline fun decodeLELong(off: Int): Long {
        checkRange(off, Long.SIZE_BYTES, size)
        return decodeLELong(bytes, off)
    }

    /**
     * Decodes the 64-bit little-endian unsigned integer at [off].
     *
     * @throws IndexOutOfBoundsException if the eight bytes aren't all within [size]
     */
    public inline fun decodeLEULong(off: Int): ULong = decodeLELong(off).toULong()

    /** Creates an iterator over the contents. */
    override fun iterator(): Iterator<Byte> = iterator {
        for (i in 0 until size) {
            yield(get(i))
        }
    }

    public fun copyInto(destination: ByteArray, destinationOffset: Int = 0, startIndex: Int = 0, endIndex: Int = size): ByteArray {
        if (startIndex < 0 || endIndex > size || startIndex > endIndex) {
            throw IndexOutOfBoundsException("Range $startIndex..$endIndex out of bounds for length $size")
        }
        return bytes.copyInto(destination, destinationOffset, startIndex, endIndex)
    }

    private companion object {
        const val MIN_CAPACITY = 64
    }
}

/**
 * Throws unless the [length] bytes from [off] are all within [size]
 */
@Suppress("NOTHING_TO_INLINE")
@InternalCryptohash
public inline fun checkRange(off: Int, length: Int, size: Int) {
    if (off < 0 || off > size - length) throwOutOfRange(off, length, size)
}

// Kept out of line so the inline accessors stay small
@InternalCryptohash
public fun throwOutOfRange(off: Int, length: Int, size: Int): Nothing = throw IndexOutOfBoundsException(
    if (length == 1) "Index $off out of bounds for length $size" else "Range $off..${off + length} out of bounds for length $size"
)
