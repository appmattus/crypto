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

package com.appmattus.crypto.internal.core.bouncycastle.ascon

import com.appmattus.crypto.internal.core.AbstractDigest
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 from
 * [NIST SP 800-232](https://doi.org/10.6028/NIST.SP.800-232).
 */
internal class Ascon private constructor(
    private val name: String,
    private val outputLength: Int,
    private val initialState: LongArray
) : AbstractDigest<Ascon>() {

    private val state = initialState.copyOf()
    private val buffer = ByteArray(RATE)
    private var bufferOffset = 0

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var off = offset
        var len = length

        if (bufferOffset != 0) {
            val count = minOf(len, RATE - bufferOffset)
            input.copyInto(buffer, bufferOffset, off, off + count)
            bufferOffset += count
            off += count
            len -= count
            if (bufferOffset == RATE) {
                absorbBlock(state, buffer, 0)
                bufferOffset = 0
            }
        }

        while (len >= RATE) {
            absorbBlock(state, input, off)
            off += RATE
            len -= RATE
        }

        if (len > 0) {
            input.copyInto(buffer, 0, off, off + len)
            bufferOffset = len
        }
    }

    override fun digest(): ByteArray {
        absorbFinalBlock(state, buffer, bufferOffset)

        val output = ByteArray(outputLength)
        var offset = 0
        while (outputLength - offset > RATE) {
            encodeLELong(state[0], output, offset)
            permute(state)
            offset += RATE
        }
        val last = ByteArray(RATE).also { encodeLELong(state[0], it, 0) }
        last.copyInto(output, offset, 0, outputLength - offset)

        reset()
        return output
    }

    override val digestLength: Int
        get() = outputLength

    override fun reset() {
        initialState.copyInto(state)
        buffer.fill(0)
        bufferOffset = 0
    }

    override fun copy(): Ascon = Ascon(name, outputLength, initialState).also {
        state.copyInto(it.state)
        buffer.copyInto(it.buffer)
        it.bufferOffset = bufferOffset
    }

    override val blockLength: Int
        get() = RATE

    override fun toString(): String = name

    internal companion object {
        private const val RATE = 8

        private const val HASH256_IV = 0x0000080100cc0002L
        private const val XOF128_IV = 0x0000080000cc0003L
        private const val CXOF128_IV = 0x0000080000cc0004L

        // Declared before the initial states, which are computed with the permutation
        private val ROUND_CONSTANTS = longArrayOf(
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
        )

        private val hash256State = initialise(HASH256_IV)
        private val xof128State = initialise(XOF128_IV)
        private val cxof128State = initialise(CXOF128_IV)

        fun hash256() = Ascon("Ascon-Hash256", 32, hash256State)

        fun xof128(outputLength: Int) = Ascon("Ascon-XOF128", outputLength, xof128State)

        /**
         * Ascon-CXOF128 absorbs the bit length of the customisation string followed by the padded customisation
         * string before the message.
         */
        fun cxof128(customisation: ByteArray, outputLength: Int): Ascon {
            val state = cxof128State.copyOf()
            state[0] = state[0] xor (customisation.size.toLong() * 8)
            permute(state)

            var offset = 0
            while (customisation.size - offset >= RATE) {
                absorbBlock(state, customisation, offset)
                offset += RATE
            }
            absorbFinalBlock(state, customisation.copyOfRange(offset, customisation.size), customisation.size - offset)

            return Ascon("Ascon-CXOF128", outputLength, state)
        }

        private fun initialise(iv: Long) = longArrayOf(iv, 0, 0, 0, 0).also { permute(it) }

        private fun absorbBlock(state: LongArray, input: ByteArray, offset: Int) {
            state[0] = state[0] xor decodeLELong(input, offset)
            permute(state)
        }

        // Absorb the final partial block of length bytes, padded with a single 1 bit
        private fun absorbFinalBlock(state: LongArray, input: ByteArray, length: Int) {
            var value = 0L
            for (i in 0 until length) {
                value = value or ((input[i].toLong() and 0xff) shl (8 * i))
            }
            state[0] = state[0] xor value xor (1L shl (8 * length))
            permute(state)
        }

        private fun permute(state: LongArray) {
            var x0 = state[0]
            var x1 = state[1]
            var x2 = state[2]
            var x3 = state[3]
            var x4 = state[4]

            for (c in ROUND_CONSTANTS) {
                x2 = x2 xor c
                val x0x4 = x0 xor x4
                val x1x2c = x1 xor x2
                val x1orx2c = x1 or x2

                val t0 = x3 xor x1orx2c xor x0 xor (x1 and x0x4)
                val t1 = x0x4 xor (x1orx2c or x3) xor (x1 and x2 and x3)
                val t2 = x1x2c xor (x4 and x3.inv())
                val t3 = (x0 or (x3 xor x4)) xor x1x2c
                val t4 = x3 xor (x1 or x4) xor (x0 and x1)

                x0 = t0 xor t0.rotateRight(19) xor t0.rotateRight(28)
                x1 = t1 xor t1.rotateRight(39) xor t1.rotateRight(61)
                x2 = (t2 xor t2.rotateRight(1) xor t2.rotateRight(6)).inv()
                x3 = t3 xor t3.rotateRight(10) xor t3.rotateRight(17)
                x4 = t4 xor t4.rotateRight(7) xor t4.rotateRight(41)
            }

            state[0] = x0
            state[1] = x1
            state[2] = x2
            state[3] = x3
            state[4] = x4
        }
    }
}
