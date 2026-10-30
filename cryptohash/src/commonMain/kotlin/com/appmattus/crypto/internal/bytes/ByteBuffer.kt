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
package com.appmattus.crypto.internal.bytes

import com.appmattus.crypto.internal.core.decodeBEInt
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.decodeLELong

/**
 * Bytes held in an array, of which the first [size] are the contents.
 *
 * The array and [size] live here, and [get] and the word decoders are final, so the hashes' inner loops call them
 * directly. With no virtual call, Kotlin/Native and the JVM can inline them. The array stays protected, so only
 * subclasses can see it.
 */
internal abstract class ByteBuffer protected constructor(
    protected var bytes: ByteArray,
    size: Int
) : Iterable<Byte> {

    var size: Int = size
        protected set

    fun add(value: ByteArray) = add(value, 0, value.size)

    abstract fun add(value: ByteArray, offset: Int, length: Int)

    abstract fun copyOf(): ByteBuffer

    /**
     * Returns the array element at the given [index].  This method can be called using the index operator.
     *
     * If the [index] is out of bounds of this array, throws an [IndexOutOfBoundsException].
     */
    operator fun get(index: Int): Byte {
        if (index < 0 || index >= size) throwOutOfRange(index, 1, size)
        return bytes[index]
    }

    /**
     * Decodes the 32-bit little-endian integer at [off], reading the bytes directly rather than one at a time through
     * [get].
     *
     * @throws IndexOutOfBoundsException if the four bytes aren't all within [size]
     */
    fun decodeLEInt(off: Int): Int {
        checkRange(off, Int.SIZE_BYTES)
        return decodeLEInt(bytes, off)
    }

    /**
     * Decodes the 32-bit big-endian integer at [off], reading the bytes directly rather than one at a time through
     * [get].
     *
     * @throws IndexOutOfBoundsException if the four bytes aren't all within [size]
     */
    fun decodeBEInt(off: Int): Int {
        checkRange(off, Int.SIZE_BYTES)
        return decodeBEInt(bytes, off)
    }

    /**
     * Decodes the 64-bit little-endian integer at [off], reading the bytes directly rather than one at a time through
     * [get].
     *
     * @throws IndexOutOfBoundsException if the eight bytes aren't all within [size]
     */
    fun decodeLELong(off: Int): Long {
        checkRange(off, Long.SIZE_BYTES)
        return decodeLELong(bytes, off)
    }

    /** Creates an iterator over the elements of the array. */
    override fun iterator(): Iterator<Byte> = iterator {
        for (i in 0 until size) {
            yield(get(i))
        }
    }

    abstract fun copyInto(destination: ByteArray, destinationOffset: Int = 0, startIndex: Int = 0, endIndex: Int = size): ByteArray

    // One check per word, against size rather than the backing array, which may be longer
    @Suppress("NOTHING_TO_INLINE")
    private inline fun checkRange(off: Int, length: Int) {
        if (off < 0 || off > size - length) throwOutOfRange(off, length, size)
    }
}

// Kept out of line, and out of the class, so the accessors stay small enough to inline
private fun throwOutOfRange(off: Int, length: Int, size: Int): Nothing = throw IndexOutOfBoundsException(
    if (length == 1) "Index $off out of bounds for length $size" else "Range $off..${off + length} out of bounds for length $size"
)
