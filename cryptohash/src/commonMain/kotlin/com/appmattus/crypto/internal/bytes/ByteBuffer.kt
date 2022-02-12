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

internal interface ByteBuffer : Iterable<Byte> {

    val size: Int

    fun add(value: ByteArray) = add(value, 0, value.size)

    fun add(value: ByteArray, offset: Int, length: Int)

    fun copyOf(): ByteBuffer

    /**
     * Returns the array element at the given [index].  This method can be called using the index operator.
     *
     * If the [index] is out of bounds of this array, throws an [IndexOutOfBoundsException] except in Kotlin/JS
     * where the behavior is unspecified.
     */
    operator fun get(index: Int): Byte

    /** Creates an iterator over the elements of the array. */
    override fun iterator(): Iterator<Byte> = iterator {
        (0 until size).forEach {
            yield(get(it))
        }
    }

    fun copyInto(destination: ByteArray, destinationOffset: Int = 0, startIndex: Int = 0, endIndex: Int = size): ByteArray
}
