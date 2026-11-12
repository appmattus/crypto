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

import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong
import com.appmattus.crypto.internal.core.rotateRight

/**
 * The five-word Ascon state, with the operations Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 make on it.
 *
 * Kotlin/JS has its own implementation holding each word as a pair of Ints, as its [Long] is an object and allocates
 * on every operation. The other platforms use [AsconStateLong].
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
internal expect class AsconState() {
    /** Sets the state to a copy of [other] */
    fun copyFrom(other: AsconState)

    /** Sets the state to the initialisation vector [iv] followed by four zero words, then applies the permutation */
    fun initialise(iv: Long)

    /** XORs [value] into the first word */
    fun xorWord0(value: Long)

    /** XORs the 8-byte little-endian block of [input] at [offset] into the first word, then applies the permutation */
    fun absorb(input: ByteArray, offset: Int)

    /**
     * XORs the final partial block, the first [length] bytes of [input] padded with a single 1 bit, into the first
     * word, then applies the permutation
     */
    fun absorbFinal(input: ByteArray, length: Int)

    /** Applies the 12-round Ascon-p permutation */
    fun permute()

    /** Writes the first word to [output] at [offset] as 8 little-endian bytes */
    fun squeeze(output: ByteArray, offset: Int)
}

/**
 * The [Long] implementation of [AsconState], for platforms whose [Long] is a 64-bit machine integer
 */
internal class AsconStateLong {
    private val state = LongArray(5)

    fun copyFrom(other: AsconStateLong) {
        other.state.copyInto(state)
    }

    fun initialise(iv: Long) {
        state.fill(0)
        state[0] = iv
        asconPermutationLong(state)
    }

    fun xorWord0(value: Long) {
        state[0] = state[0] xor value
    }

    fun absorb(input: ByteArray, offset: Int) {
        state[0] = state[0] xor decodeLELong(input, offset)
        asconPermutationLong(state)
    }

    fun absorbFinal(input: ByteArray, length: Int) {
        var value = 0L
        for (i in 0 until length) {
            value = value or ((input[i].toLong() and 0xff) shl (8 * i))
        }
        state[0] = state[0] xor value xor (1L shl (8 * length))
        asconPermutationLong(state)
    }

    fun permute() {
        asconPermutationLong(state)
    }

    fun squeeze(output: ByteArray, offset: Int) {
        encodeLELong(state[0], output, offset)
    }
}

/**
 * The 12-round Ascon-p permutation of the five-word [state]
 */
internal fun asconPermutationLong(state: LongArray) {
    var x0 = state[0]
    var x1 = state[1]
    var x2 = state[2]
    var x3 = state[3]
    var x4 = state[4]

    for (c in ASCON_ROUND_CONSTANTS) {
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

/** The round constants of the 12 rounds, each XORed into the low byte of x2 */
internal val ASCON_ROUND_CONSTANTS = longArrayOf(
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
)
