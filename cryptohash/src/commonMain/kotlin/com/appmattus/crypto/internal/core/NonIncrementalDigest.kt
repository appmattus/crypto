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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.bytes.ByteArrayArray
import com.appmattus.crypto.internal.bytes.ByteBuffer

/**
 * Allows non-incremental hashing algorithms to be used incrementally by storing data in an internal buffer
 */
internal abstract class NonIncrementalDigest<D : NonIncrementalDigest<D>> : Digest<D> {

    private var internalBuffer = ByteArray(0)

    final override fun update(input: Byte) {
        internalBuffer += input
    }

    final override fun update(input: ByteArray) {
        internalBuffer += input
    }

    final override fun update(input: ByteArray, offset: Int, length: Int) {
        internalBuffer += input.sliceArray(offset until (offset + length))
    }

    final override fun digest(input: ByteArray): ByteArray {
        val buffer = ByteArrayArray().apply {
            add(internalBuffer)
            add(input)
        }

        process(buffer, 0, buffer.size)

        return digest()
    }

    final override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    abstract fun process(input: ByteBuffer, offset: Int, length: Int)

    final override fun reset() {
        internalBuffer = ByteArray(0)
    }

    /**
     * This function copies the internal buffering state to some
     * other instance of a class extending `NonIncremetalDigest`.
     * It returns a reference to the copy. This method is intended
     * to be called by the implementation of the [.copy]
     * method.
     *
     * @param dest   the copy
     * @return the value `dest`
     */
    protected open fun copyState(dest: D): D {
        dest.internalBuffer = internalBuffer.copyOf()
        return dest
    }
}
