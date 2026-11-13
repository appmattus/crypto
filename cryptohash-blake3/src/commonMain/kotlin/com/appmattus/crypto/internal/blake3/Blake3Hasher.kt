/*
 * Copyright 2021-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.blake3

import com.appmattus.crypto.Hasher

/**
 * A [Hasher] for BLAKE3 with output size of [digestLength] bytes, over a [Blake3Core] from [newCore], which sets the mode
 */
internal class Blake3Hasher(override val digestLength: Int, private val newCore: () -> Blake3Core) : Hasher {

    private var hasher = newCore()

    /**
     * Buffer for single byte update method
     */
    private val singleByte = ByteArray(1)

    override fun update(input: Byte): Hasher {
        singleByte[0] = input
        update(singleByte, 0, 1)
        return this
    }

    override fun update(input: ByteArray): Hasher {
        update(input, 0, input.size)
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        hasher.update(input, offset, length)
        return this
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        digest(digest, 0, digestLength)
        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        hasher.update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        hasher.digest(output, offset, length)
        reset()
        return length
    }

    override fun reset() {
        hasher.reset()
    }

    override fun copy(): Blake3Hasher {
        return Blake3Hasher(digestLength, newCore).also {
            it.hasher = hasher.copyOf()
        }
    }

    override fun toString() = "Blake3-${digestLength * 8}"
}
