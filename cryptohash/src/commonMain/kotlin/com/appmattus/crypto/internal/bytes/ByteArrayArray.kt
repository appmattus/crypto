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

package com.appmattus.crypto.internal.bytes

internal class ByteArrayArray : ByteBuffer {

    private var bytes: MutableList<ByteArray> = mutableListOf()
    private var sizes: MutableList<Int> = mutableListOf()
    private var offsets: MutableList<Int> = mutableListOf()

    override var size: Int = 0
        private set

    override fun add(value: ByteArray, offset: Int, length: Int) {
        if (length > 0) {
            bytes += value
            sizes += length
            size += length
            offsets += offset
        }
    }

    /**
     * Returns the array element at the given [index].  This method can be called using the index operator.
     *
     * If the [index] is out of bounds of this array, throws an [IndexOutOfBoundsException] except in Kotlin/JS
     * where the behavior is unspecified.
     */
    override operator fun get(index: Int): Byte {
        var listIndex = 0
        var totalIndex = 0

        if (bytes.size == 0) {
            throw IndexOutOfBoundsException("Index $index out of bounds for length 0")
        }

        while (index >= totalIndex + sizes[listIndex]) {
            totalIndex += sizes[listIndex]
            listIndex++

            if (listIndex >= bytes.size) {
                throw IndexOutOfBoundsException("Index $index out of bounds for length $size")
            }
        }

        return bytes[listIndex][offsets[listIndex] + index - totalIndex]
    }
}
