/*
 * Copyright 2021 Appmattus Limited
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

package com.appmattus.crypto.internal.core.blake3

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest

internal class Blake3(private val parameters: Algorithm.Blake3) : Digest<Blake3> {

    private var hasher = when (parameters) {
        is Algorithm.Blake3.Keyed -> Hasher.newKeyedHasher(parameters.key)
        is Algorithm.Blake3.DeriveKey -> Hasher.newKeyDerivationHasher(parameters.context)
        else -> Hasher.newInstance()
    }

    /**
     * Buffer for single byte update method
     */
    private val singleByte = ByteArray(1)

    override fun update(input: Byte) {
        singleByte[0] = input
        update(singleByte, 0, 1)
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        hasher.update(input, offset, length)
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

    override val digestLength: Int
        get() = parameters.digestLength

    override fun reset() {
        hasher.reset()
    }

    override fun copy(): Blake3 {
        return Blake3(parameters).also {
            it.hasher = hasher.copyOf()
        }
    }

    override val blockLength: Int
        get() = 64

    override fun toString() = "Blake3"
}
