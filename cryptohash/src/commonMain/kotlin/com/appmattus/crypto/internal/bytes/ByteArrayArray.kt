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

    override var size: Int = 0
        private set

    override fun add(value: ByteArray, offset: Int, length: Int) {
        if (length > 0) {
            bytes += value.copyOfRange(offset, offset + length)
            sizes += length
            size += length
        }
    }

    override fun copyOf() = ByteArrayArray().apply {
        for (i in 0 until bytes.size) {
            add(bytes[i].copyOf(), 0, sizes[i])
        }
    }

    /**
     * Returns the array element at the given [index].  This method can be called using the index operator.
     *
     * If the [index] is out of bounds of this array, throws an [IndexOutOfBoundsException] except in Kotlin/JS
     * where the behavior is unspecified.
     */
    override operator fun get(index: Int): Byte {
        val pos = position(index)
        return bytes[pos.first][pos.second]
    }

    private fun position(index: Int): Pair<Int, Int> {
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

        return Pair(listIndex, index - totalIndex)
    }

    override fun copyInto(destination: ByteArray, destinationOffset: Int, startIndex: Int, endIndex: Int): ByteArray {
        var destOffset = destinationOffset
        var len = endIndex - startIndex
        var index = startIndex

        while (len > 0) {
            println("\n")
            println("destOffset: $destOffset")
            println("len: $len")
            println("index: $index")


            val pos = position(index)
            println("pos: $pos")

            val available = sizes[pos.first] - pos.second
            println("available: $available")

            if (available >= len) {
                println("copying all bytes")
                // this array contains all the data we need...
                bytes[pos.first].copyInto(destination, destOffset, pos.second, pos.second + len)
                len = 0
                destOffset += len
                index += len
            } else {
                println("copying partial bytes")

                // partial bytes
                bytes[pos.first].copyInto(destination, destOffset, pos.second, pos.second + available)
                len -= available
                destOffset += available
                index += available
            }

            println("destination: ${destination.toList()}")
        }

        return destination
    }
}
