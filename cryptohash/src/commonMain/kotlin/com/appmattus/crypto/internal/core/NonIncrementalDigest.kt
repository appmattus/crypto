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

    private var internalBuffer = ByteArrayArray()

    final override fun update(input: Byte) {
        internalBuffer.add(byteArrayOf(input))
    }

    final override fun update(input: ByteArray) {
        internalBuffer.add(input)
    }

    final override fun update(input: ByteArray, offset: Int, length: Int) {
        internalBuffer.add(input, offset, length)
    }

    final override fun digest(input: ByteArray): ByteArray {
        internalBuffer.add(input)
        process(internalBuffer)

        return digest()
    }

    final override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    abstract fun process(input: ByteBuffer)

    final override fun reset() {
        internalBuffer = ByteArrayArray()
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
