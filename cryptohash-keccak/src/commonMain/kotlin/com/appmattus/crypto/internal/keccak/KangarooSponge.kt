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

package com.appmattus.crypto.internal.keccak

import com.appmattus.crypto.internal.core.copyBytes

/**
 * Keccak sponge using the 12 round Keccak-p[1600, 12] permutation with padding left to the caller, as used by
 * [KangarooTwelve].
 */
internal class KangarooSponge private constructor(
    val rateBytes: Int,
    private val state: KeccakState,
    private val queue: ByteArray,
    private var bytesInQueue: Int,
    private var squeezing: Boolean
) {

    constructor(strength: Int) : this(
        rateBytes = (1600 - (strength shl 1)) shr 3,
        state = KeccakState(),
        queue = ByteArray((1600 - (strength shl 1)) shr 3),
        bytesInQueue = 0,
        squeezing = false
    )

    fun copy(): KangarooSponge =
        KangarooSponge(rateBytes, KeccakState().apply { copyFrom(state) }, queue.copyOf(), bytesInQueue, squeezing)

    fun initSponge() {
        state.clear()
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
                copyBytes(data, offset + count, queue, bytesInQueue, partialBlock)
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
        state.absorb(data, offset, rateBytes shr 3)
        permute()
    }

    private fun extract() = state.extract(queue, rateBytes shr 3)

    private fun permute() = state.permute(ROUNDS)

    private companion object {
        // Keccak-p[1600, 12]: the last 12 of Keccak-f[1600]'s 24 rounds
        private const val ROUNDS = 12
    }
}
