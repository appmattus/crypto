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

package com.appmattus.crypto.internal.core.bouncycastle.kangaroo

/**
 * Keccak sponge using the 12 round Keccak-p[1600, 12] permutation with padding left to the caller, as used by
 * [KangarooTwelve].
 */
internal class KangarooSponge private constructor(
    val rateBytes: Int,
    private val state: LongArray,
    private val queue: ByteArray,
    private var bytesInQueue: Int,
    private var squeezing: Boolean
) {

    constructor(strength: Int) : this(
        rateBytes = (1600 - (strength shl 1)) shr 3,
        state = LongArray(25),
        queue = ByteArray((1600 - (strength shl 1)) shr 3),
        bytesInQueue = 0,
        squeezing = false
    )

    fun copy(): KangarooSponge = KangarooSponge(rateBytes, state.copyOf(), queue.copyOf(), bytesInQueue, squeezing)

    fun initSponge() {
        state.fill(0)
        queue.fill(0)
        bytesInQueue = 0
        squeezing = false
    }

    fun absorb(data: ByteArray, offset: Int, length: Int) {
        check(!squeezing) { "attempt to absorb while squeezing" }

        var count = 0
        while (count < length) {
            if (bytesInQueue == rateBytes) {
                absorbBlock(queue, 0)
                bytesInQueue = 0
            }
            if (bytesInQueue == 0 && count <= length - rateBytes) {
                do {
                    absorbBlock(data, offset + count)
                    count += rateBytes
                } while (count <= length - rateBytes)
            } else {
                val partialBlock = minOf(rateBytes - bytesInQueue, length - count)
                data.copyInto(queue, bytesInQueue, offset + count, offset + count + partialBlock)
                bytesInQueue += partialBlock
                count += partialBlock
            }
        }
    }

    private fun padAndSwitchToSqueezingPhase() {
        queue.fill(0, bytesInQueue, rateBytes)
        queue[rateBytes - 1] = (queue[rateBytes - 1].toInt() xor 0x80).toByte()
        absorbBlock(queue, 0)
        extract()
        bytesInQueue = rateBytes
        squeezing = true
    }

    fun squeeze(output: ByteArray, offset: Int, length: Int) {
        if (!squeezing) {
            padAndSwitchToSqueezingPhase()
        }

        var i = 0
        while (i < length) {
            if (bytesInQueue == 0) {
                permute()
                extract()
                bytesInQueue = rateBytes
            }
            val partialBlock = minOf(bytesInQueue, length - i)
            queue.copyInto(output, offset + i, rateBytes - bytesInQueue, rateBytes - bytesInQueue + partialBlock)
            bytesInQueue -= partialBlock
            i += partialBlock
        }
    }

    private fun absorbBlock(data: ByteArray, offset: Int) {
        for (i in 0 until (rateBytes shr 3)) {
            var value = 0L
            for (j in 7 downTo 0) {
                value = (value shl 8) or (data[offset + i * 8 + j].toLong() and 0xff)
            }
            state[i] = state[i] xor value
        }
        permute()
    }

    private fun extract() {
        for (i in 0 until (rateBytes shr 3)) {
            val value = state[i]
            for (j in 0 until 8) {
                queue[i * 8 + j] = (value ushr (8 * j)).toByte()
            }
        }
    }

    private fun permute() {
        val a = state
        val c = LongArray(5)
        for (round in ROUND_CONSTANTS.indices) {
            // theta
            for (x in 0 until 5) {
                c[x] = a[x] xor a[x + 5] xor a[x + 10] xor a[x + 15] xor a[x + 20]
            }
            for (x in 0 until 5) {
                val d = c[(x + 4) % 5] xor c[(x + 1) % 5].rotateLeft(1)
                for (y in 0 until 25 step 5) {
                    a[x + y] = a[x + y] xor d
                }
            }

            // rho and pi
            var current = a[1]
            for (t in 0 until 24) {
                val lane = PI_LANES[t]
                val next = a[lane]
                a[lane] = current.rotateLeft(RHO_OFFSETS[t])
                current = next
            }

            // chi
            for (y in 0 until 25 step 5) {
                for (x in 0 until 5) {
                    c[x] = a[y + x]
                }
                for (x in 0 until 5) {
                    a[y + x] = c[x] xor (c[(x + 1) % 5].inv() and c[(x + 2) % 5])
                }
            }

            // iota
            a[0] = a[0] xor ROUND_CONSTANTS[round]
        }
    }

    private companion object {
        // The last 12 of the 24 Keccak-f[1600] round constants
        private val ROUND_CONSTANTS = longArrayOf(
            0x000000008000808buL.toLong(), 0x800000000000008buL.toLong(), 0x8000000000008089uL.toLong(),
            0x8000000000008003uL.toLong(), 0x8000000000008002uL.toLong(), 0x8000000000000080uL.toLong(),
            0x000000000000800auL.toLong(), 0x800000008000000auL.toLong(), 0x8000000080008081uL.toLong(),
            0x8000000000008080uL.toLong(), 0x0000000080000001uL.toLong(), 0x8000000080008008uL.toLong()
        )

        private val RHO_OFFSETS = intArrayOf(
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
        )

        private val PI_LANES = intArrayOf(
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
        )
    }
}
