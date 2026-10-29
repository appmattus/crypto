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

/**
 * An abstract class rather than an interface, as Kotlin/Native dispatches class calls more cheaply than interface
 * calls, which matters for the word decoders called in every hash's inner loop
 */
internal abstract class ByteBuffer : Iterable<Byte> {

    abstract val size: Int

    fun add(value: ByteArray) = add(value, 0, value.size)

    abstract fun add(value: ByteArray, offset: Int, length: Int)

    abstract fun copyOf(): ByteBuffer

    /**
     * Returns the array element at the given [index].  This method can be called using the index operator.
     *
     * If the [index] is out of bounds of this array, throws an [IndexOutOfBoundsException] except in Kotlin/JS
     * where the behavior is unspecified.
     */
    abstract operator fun get(index: Int): Byte

    /**
     * Decodes the 32-bit little-endian integer at [off], reading the bytes directly rather than one at a time through
     * [get].
     *
     * @throws IndexOutOfBoundsException if the four bytes aren't all within [size]
     */
    abstract fun decodeLEInt(off: Int): Int

    /**
     * Decodes the 32-bit big-endian integer at [off], reading the bytes directly rather than one at a time through
     * [get].
     *
     * @throws IndexOutOfBoundsException if the four bytes aren't all within [size]
     */
    abstract fun decodeBEInt(off: Int): Int

    /**
     * Decodes the 64-bit little-endian integer at [off], reading the bytes directly rather than one at a time through
     * [get].
     *
     * @throws IndexOutOfBoundsException if the eight bytes aren't all within [size]
     */
    abstract fun decodeLELong(off: Int): Long

    /** Creates an iterator over the elements of the array. */
    override fun iterator(): Iterator<Byte> = iterator {
        for (i in 0 until size) {
            yield(get(i))
        }
    }

    abstract fun copyInto(destination: ByteArray, destinationOffset: Int = 0, startIndex: Int = 0, endIndex: Int = size): ByteArray
}
