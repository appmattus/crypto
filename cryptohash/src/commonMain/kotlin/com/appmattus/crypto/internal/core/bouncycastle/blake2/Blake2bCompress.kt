/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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

package com.appmattus.crypto.internal.core.bouncycastle.blake2

import com.appmattus.crypto.internal.core.decodeLELong

/**
 * Compresses one 128-byte block of [message] from [messagePos] into the eight-word [chainValue], using the already
 * initialised sixteen-word [internalState] as the working state and [messageWords] as scratch for the block's sixteen
 * message words.
 *
 * Kotlin/JS has its own implementation, as its [Long] is an object and allocates on every operation.
 */
internal expect fun blake2bCompress(
    chainValue: LongArray,
    internalState: LongArray,
    messageWords: LongArray,
    message: ByteArray,
    messagePos: Int
)

/**
 * The [Long] implementation of [blake2bCompress], for platforms whose [Long] is a 64-bit machine integer
 */
internal fun blake2bCompressLong(
    chainValue: LongArray,
    internalState: LongArray,
    messageWords: LongArray,
    message: ByteArray,
    messagePos: Int
) {
    val m = messageWords
    for (j in 0..15) {
        m[j] = decodeLELong(message, messagePos + j * 8)
    }
    for (round in 0 until BLAKE2B_ROUNDS) {
        val s = BLAKE2B_SIGMA[round]
        // G applied to the columns, then the diagonals, of the internal state
        g(internalState, m[s[0].toInt()], m[s[1].toInt()], 0, 4, 8, 12)
        g(internalState, m[s[2].toInt()], m[s[3].toInt()], 1, 5, 9, 13)
        g(internalState, m[s[4].toInt()], m[s[5].toInt()], 2, 6, 10, 14)
        g(internalState, m[s[6].toInt()], m[s[7].toInt()], 3, 7, 11, 15)
        g(internalState, m[s[8].toInt()], m[s[9].toInt()], 0, 5, 10, 15)
        g(internalState, m[s[10].toInt()], m[s[11].toInt()], 1, 6, 11, 12)
        g(internalState, m[s[12].toInt()], m[s[13].toInt()], 2, 7, 8, 13)
        g(internalState, m[s[14].toInt()], m[s[15].toInt()], 3, 4, 9, 14)
    }

    // update chain values:
    for (offset in chainValue.indices) {
        chainValue[offset] = chainValue[offset] xor internalState[offset] xor internalState[offset + 8]
    }
}

@Suppress("LongParameterList")
private fun g(internalState: LongArray, m1: Long, m2: Long, posA: Int, posB: Int, posC: Int, posD: Int) {
    internalState[posA] = internalState[posA] + internalState[posB] + m1
    internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(32)
    internalState[posC] = internalState[posC] + internalState[posD]
    internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(24) // replaces 25 of BLAKE
    internalState[posA] = internalState[posA] + internalState[posB] + m2
    internalState[posD] = (internalState[posD] xor internalState[posA]).rotateRight(16)
    internalState[posC] = internalState[posC] + internalState[posD]
    internalState[posB] = (internalState[posB] xor internalState[posC]).rotateRight(63) // replaces 11 of BLAKE
}

/** The number of rounds */
internal const val BLAKE2B_ROUNDS = 12

/** The message word permutations for each round */
internal val BLAKE2B_SIGMA = arrayOf(
    byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    byteArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    byteArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    byteArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    byteArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    byteArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    byteArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    byteArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    byteArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
)
