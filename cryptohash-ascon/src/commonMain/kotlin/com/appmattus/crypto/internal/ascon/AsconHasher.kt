/*
 * Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Translation to Kotlin:
 *
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

package com.appmattus.crypto.internal.ascon

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.AbstractHasher
import com.appmattus.crypto.internal.core.copyBytes

/**
 * Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 from
 * [NIST SP 800-232](https://doi.org/10.6028/NIST.SP.800-232).
 */
internal class AsconHasher private constructor(
    private val name: String,
    private val outputLength: Int,
    private val initialState: AsconState
) : AbstractHasher() {

    private val state = AsconState().apply { copyFrom(initialState) }
    private val buffer = ByteArray(RATE)
    private var bufferOffset = 0

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        var off = offset
        var len = length

        if (bufferOffset != 0) {
            val count = minOf(len, RATE - bufferOffset)
            copyBytes(input, off, buffer, bufferOffset, count)
            bufferOffset += count
            off += count
            len -= count
            if (bufferOffset == RATE) {
                state.absorb(buffer, 0)
                bufferOffset = 0
            }
        }

        while (len >= RATE) {
            state.absorb(input, off)
            off += RATE
            len -= RATE
        }

        if (len > 0) {
            copyBytes(input, off, buffer, 0, len)
            bufferOffset = len
        }
        return this
    }

    override fun digest(): ByteArray {
        state.absorbFinal(buffer, bufferOffset)

        val output = ByteArray(outputLength)
        var offset = 0
        while (outputLength - offset > RATE) {
            state.squeeze(output, offset)
            state.permute()
            offset += RATE
        }
        val last = ByteArray(RATE).also { state.squeeze(it, 0) }
        last.copyInto(output, offset, 0, outputLength - offset)

        reset()
        return output
    }

    override val digestLength: Int
        get() = outputLength

    override fun reset() {
        state.copyFrom(initialState)
        buffer.fill(0)
        bufferOffset = 0
    }

    override fun copy(): AsconHasher = AsconHasher(name, outputLength, initialState).also {
        it.state.copyFrom(state)
        buffer.copyInto(it.buffer)
        it.bufferOffset = bufferOffset
    }

    override fun toString(): String = name

    internal companion object {
        private const val RATE = 8

        private const val HASH256_IV = 0x0000080100cc0002L
        private const val XOF128_IV = 0x0000080000cc0003L
        private const val CXOF128_IV = 0x0000080000cc0004L

        private val hash256State = initialise(HASH256_IV)
        private val xof128State = initialise(XOF128_IV)
        private val cxof128State = initialise(CXOF128_IV)

        fun hash256() = AsconHasher("Ascon-Hash256", 32, hash256State)

        fun xof128(outputLength: Int) = AsconHasher("Ascon-XOF128", outputLength, xof128State)

        /**
         * Ascon-CXOF128 absorbs the bit length of the customisation string followed by the padded customisation
         * string before the message.
         */
        fun cxof128(customisation: ByteArray, outputLength: Int): AsconHasher {
            val state = AsconState().apply { copyFrom(cxof128State) }
            state.xorWord0(customisation.size.toLong() * 8)
            state.permute()

            var offset = 0
            while (customisation.size - offset >= RATE) {
                state.absorb(customisation, offset)
                offset += RATE
            }
            state.absorbFinal(customisation.copyOfRange(offset, customisation.size), customisation.size - offset)

            return AsconHasher("Ascon-CXOF128", outputLength, state)
        }

        private fun initialise(iv: Long) = AsconState().apply { initialise(iv) }
    }
}
