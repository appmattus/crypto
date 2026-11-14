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

package com.appmattus.crypto.internal.skein

import com.appmattus.crypto.Hasher

/**
 * This class implements the Skein-XXXX-XXX digest algorithm
 */
internal class SkeinHasher(
    private val blockSizeBits: Int,
    private val outputSizeBits: Int,
    private val key: ByteArray? = null
) : Hasher {

    init {
        require(blockSizeBits in listOf(256, 512, 1024))
        require(outputSizeBits in listOf(128, 160, 224, 256, 384, 512, 1024))
    }

    override fun toString() = "Skein-$blockSizeBits-$outputSizeBits"

    private var engine = SkeinEngine(blockSizeBits, outputSizeBits).apply {
        val params = if (key != null && key.isNotEmpty()) {
            SkeinParameters.Builder().setKey(key).build()
        } else {
            null
        }

        init(params)
    }

    override fun update(input: Byte): Hasher {
        engine.update(input)
        return this
    }

    override fun update(input: ByteArray): Hasher {
        engine.update(input, 0, input.size)
        return this
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        engine.update(input, offset, length)
        return this
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        engine.doFinal(digest, 0)
        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        require(length >= digest.size) { "partial digests not returned" }
        require(output.size - offset >= digest.size) { "insufficient space in the output buffer to store the digest" }

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = outputSizeBits shr 3

    override fun reset() {
        engine.reset()
    }

    override fun copy(): SkeinHasher {
        return SkeinHasher(blockSizeBits, outputSizeBits).also {
            it.engine = engine.copy()
        }
    }
}
