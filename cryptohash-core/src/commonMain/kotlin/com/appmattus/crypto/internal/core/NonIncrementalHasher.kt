/*
 * Copyright 2026 Appmattus Limited
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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.InternalCryptohash
import com.appmattus.crypto.internal.bytes.ByteBuffer

/**
 * A [Hasher] for an algorithm that can only hash its whole input at once. It buffers everything passed to [update],
 * then calls [hash] with all of it on [digest].
 *
 * The algorithm is supplied as the [hash] function rather than by subclassing, so it can be a plain function of the
 * input with no state of its own. [hash] must not keep or change the buffer it is given, and must return a new array
 * of [digestLength] bytes. [copy] copies only the buffer and shares [hash].
 *
 * @param name what [toString] returns
 */
@InternalCryptohash
public class NonIncrementalHasher(
    private val name: String,
    override val digestLength: Int,
    private val hash: (input: ByteBuffer) -> ByteArray
) : Hasher {

    private var buffer = ByteBuffer()

    override fun update(input: Byte): Hasher = apply { buffer.add(input) }

    override fun update(input: ByteArray): Hasher = apply { buffer.add(input) }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher = apply { buffer.add(input, offset, length) }

    override fun digest(): ByteArray {
        val digest = hash(buffer)
        reset()
        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        buffer.add(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override fun reset() {
        buffer = ByteBuffer()
    }

    override fun copy(): Hasher = NonIncrementalHasher(name, digestLength, hash).also { it.buffer = buffer.copyOf() }

    override fun toString(): String = name
}
