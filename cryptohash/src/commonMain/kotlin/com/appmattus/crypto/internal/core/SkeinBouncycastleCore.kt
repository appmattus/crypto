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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.bouncycastle.skein.SkeinEngine
import com.appmattus.crypto.internal.core.bouncycastle.skein.SkeinParameters

/**
 * This class implements the Skein-XXXX-XXX digest algorithm
 */
@Suppress("MagicNumber")
internal class SkeinBouncycastleCore(
    private val blockSizeBits: Int,
    private val outputSizeBits: Int,
    private val key: ByteArray? = null
) : Digest<SkeinBouncycastleCore> {

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

    override fun update(input: Byte) {
        engine.update(input)
    }

    override fun update(input: ByteArray) {
        engine.update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        engine.update(input, offset, length)
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

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = outputSizeBits shr 3

    override val blockLength: Int
        get() = blockSizeBits shr 3

    override fun reset() {
        engine.reset()
    }

    override fun copy(): SkeinBouncycastleCore {
        return SkeinBouncycastleCore(blockSizeBits, outputSizeBits).also {
            it.engine = engine.copy()
        }
    }

    companion object {
        fun create(parameters: Algorithm.Skein): SkeinBouncycastleCore {
            return when (parameters) {
                is Algorithm.Skein.Keyed -> SkeinBouncycastleCore(parameters.blockSizeBits, parameters.outputSizeBits, parameters.key)
                else -> SkeinBouncycastleCore(parameters.blockSizeBits, parameters.outputSizeBits, null)
            }
        }
    }
}
