/*
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

import com.appmattus.crypto.internal.core.decodeLeLong
import com.appmattus.crypto.internal.core.encodeLeLong

/**
 * The 25-lane Keccak state, with the operations the Keccak sponges make on it.
 *
 * Kotlin/JS has its own implementation holding each lane as a pair of Ints, as its [Long] is an object and allocates
 * on every operation. The other platforms use [KeccakStateLong].
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
internal expect class KeccakState() {
    /** Sets every lane to zero */
    fun clear()

    /** Sets the state to a copy of [other] */
    fun copyFrom(other: KeccakState)

    /** XORs [lanes] 8-byte little-endian words of [data], from [offset], into the first [lanes] lanes */
    fun absorb(data: ByteArray, offset: Int, lanes: Int)

    /** XORs the low [bits] bits, 1 to 63, of the 8-byte little-endian word of [data] at [offset] into [lane] */
    fun absorbPartial(lane: Int, data: ByteArray, offset: Int, bits: Int)

    /** Flips the top bit of [lane] */
    fun flipTopBit(lane: Int)

    /** Applies Keccak-p[1600, [rounds]]: the last [rounds] rounds of Keccak-f[1600], which has [KECCAK_F_ROUNDS] */
    fun permute(rounds: Int)

    /** Writes the first [lanes] lanes to [output], from 0, as 8-byte little-endian words */
    fun extract(output: ByteArray, lanes: Int)
}

/**
 * The [Long] implementation of [KeccakState], for platforms whose [Long] is a 64-bit machine integer
 */
internal class KeccakStateLong {
    private val state = LongArray(25)

    fun clear() {
        state.fill(0)
    }

    fun copyFrom(other: KeccakStateLong) {
        other.state.copyInto(state)
    }

    fun absorb(data: ByteArray, offset: Int, lanes: Int) {
        var off = offset
        for (i in 0 until lanes) {
            state[i] = state[i] xor decodeLeLong(data, off)
            off += 8
        }
    }

    fun absorbPartial(lane: Int, data: ByteArray, offset: Int, bits: Int) {
        val mask = (1L shl bits) - 1L
        state[lane] = state[lane] xor (decodeLeLong(data, offset) and mask)
    }

    fun flipTopBit(lane: Int) {
        state[lane] = state[lane] xor (1L shl 63)
    }

    fun permute(rounds: Int) = keccakPermutationLong(state, rounds)

    fun extract(output: ByteArray, lanes: Int) {
        var off = 0
        for (i in 0 until lanes) {
            encodeLeLong(state[i], output, off)
            off += 8
        }
    }
}
