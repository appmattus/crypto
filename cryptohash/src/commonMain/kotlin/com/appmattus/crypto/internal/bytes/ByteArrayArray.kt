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
 * A [ByteBuffer] backed by a single growable array, so [get] is constant time however many arrays were added
 */
internal class ByteArrayArray private constructor(private var bytes: ByteArray, size: Int) : ByteBuffer() {

    constructor() : this(ByteArray(0), 0)

    override var size: Int = size
        private set

    override fun add(value: ByteArray, offset: Int, length: Int) {
        if (length > 0) {
            if (size + length > bytes.size) {
                bytes = bytes.copyOf(maxOf(size + length, bytes.size * 2, MIN_CAPACITY))
            }
            value.copyInto(bytes, size, offset, offset + length)
            size += length
        }
    }

    override fun copyOf() = ByteArrayArray(bytes.copyOf(size), size)

    /**
     * Returns the array element at the given [index].  This method can be called using the index operator.
     *
     * If the [index] is out of bounds of this array, throws an [IndexOutOfBoundsException].
     */
    override operator fun get(index: Int): Byte {
        if (index < 0 || index >= size) {
            throw IndexOutOfBoundsException("Index $index out of bounds for length $size")
        }
        return bytes[index]
    }

    override fun decodeLEInt(off: Int): Int {
        checkRange(off, Int.SIZE_BYTES)
        return decodeLEInt(bytes, off)
    }

    override fun decodeBEInt(off: Int): Int {
        checkRange(off, Int.SIZE_BYTES)
        return decodeBEInt(bytes, off)
    }

    override fun decodeLELong(off: Int): Long {
        checkRange(off, Long.SIZE_BYTES)
        return decodeLELong(bytes, off)
    }

    // One check per word, against size rather than the backing array, which may be longer
    @Suppress("NOTHING_TO_INLINE")
    private inline fun checkRange(off: Int, length: Int) {
        if (off < 0 || off > size - length) throwOutOfRange(off, length)
    }

    // Kept out of line so the decoders stay small enough to inline
    private fun throwOutOfRange(off: Int, length: Int): Nothing =
        throw IndexOutOfBoundsException("Range $off..${off + length} out of bounds for length $size")

    override fun copyInto(destination: ByteArray, destinationOffset: Int, startIndex: Int, endIndex: Int): ByteArray {
        if (startIndex < 0 || endIndex > size || startIndex > endIndex) {
            throw IndexOutOfBoundsException("Range $startIndex..$endIndex out of bounds for length $size")
        }
        return bytes.copyInto(destination, destinationOffset, startIndex, endIndex)
    }

    private companion object {
        const val MIN_CAPACITY = 64
    }
}
