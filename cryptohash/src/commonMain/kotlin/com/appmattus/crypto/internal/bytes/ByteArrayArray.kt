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
 * A [ByteBuffer] backed by a single growable array, so [get] is constant time however many arrays were added
 */
internal class ByteArrayArray private constructor(bytes: ByteArray, size: Int) : ByteBuffer(bytes, size) {

    constructor() : this(ByteArray(0), 0)

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
