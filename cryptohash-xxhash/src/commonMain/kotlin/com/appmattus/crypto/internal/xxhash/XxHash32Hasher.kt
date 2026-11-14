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

package com.appmattus.crypto.internal.xxhash

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.AbstractHasher
import com.appmattus.crypto.internal.core.copyBytes
import com.appmattus.crypto.internal.core.decodeLeInt
import com.appmattus.crypto.internal.core.encodeBeInt
import com.appmattus.crypto.internal.core.rotateLeft

/**
 * @property seed A seed for generate digest. Default is 0.
 */
internal class XxHash32Hasher(private val seed: Int = 0) : AbstractHasher() {

    private var state = State32()

    init {
        reset()
    }

    private fun round(seed: Int, input: Int): Int {
        var seed2 = seed
        seed2 += input * prime2
        seed2 = seed2.rotateLeft(13)
        seed2 *= prime1

        return seed2
    }

    private fun avalanche(h: Int): Int {
        var h2 = h
        h2 = h2 xor (h2 ushr 15)
        h2 *= prime2
        h2 = h2 xor (h2 ushr 13)
        h2 *= prime3
        h2 = h2 xor (h2 ushr 16)
        return h2
    }

    private fun finalize(h: Int, array: ByteArray, len: Int): Int {
        var index = 0
        var h2 = h

        fun process1() {
            h2 += ((array[index].toInt() and 0xff) * prime5)

            index += 1
            h2 = h2.rotateLeft(11) * prime1
        }

        fun process4() {
            h2 += decodeLeInt(array, index) * prime3

            index += 4
            h2 = h2.rotateLeft(17) * prime4
        }

        val x = len and 15

        repeat(x shr 2) { process4() }
        repeat(x and 3) { process1() }

        return avalanche(h2)
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        var index = 0

        state.totalLen += length
        state.largeLen = (length >= 16) || (state.totalLen >= 16)

        if (state.memSize + length < 16) {
            // fill in tmp buffer
            copyBytes(input, index + offset, state.mem, state.memSize, length)
            state.memSize += length

            return this
        }

        if (state.memSize > 0) {
            // some data left from previous update
            copyBytes(input, index + offset, state.mem, state.memSize, 16 - state.memSize)

            state.v1 = round(state.v1, decodeLeInt(state.mem, 0))
            state.v2 = round(state.v2, decodeLeInt(state.mem, 4))
            state.v3 = round(state.v3, decodeLeInt(state.mem, 8))
            state.v4 = round(state.v4, decodeLeInt(state.mem, 12))

            index += 16 - state.memSize
            state.memSize = 0
        }

        if (index <= length - 16) {
            val limit = length - 16

            do {
                state.v1 = round(state.v1, decodeLeInt(input, index + offset))
                index += 4

                state.v2 = round(state.v2, decodeLeInt(input, index + offset))
                index += 4

                state.v3 = round(state.v3, decodeLeInt(input, index + offset))
                index += 4

                state.v4 = round(state.v4, decodeLeInt(input, index + offset))
                index += 4
            } while (index <= limit)
        }

        if (index < length) {
            copyBytes(input, index + offset, state.mem, 0, length - index)

            state.memSize = length - index
        }
        return this
    }

    override fun update(input: Byte): Hasher {
        // Buffer a single byte directly unless it completes a stripe
        if (state.memSize < 15) {
            state.mem[state.memSize++] = input
            state.totalLen += 1
            state.largeLen = state.totalLen >= 16
            return this
        }
        return super.update(input)
    }

    override fun digest(): ByteArray {
        var h: Int = if (state.largeLen) {
            state.v1.rotateLeft(1) +
                    state.v2.rotateLeft(7) +
                    state.v3.rotateLeft(12) +
                    state.v4.rotateLeft(18)
        } else {
            // state.v3 == seed
            state.v3 + prime5
        }

        h += state.totalLen

        h = finalize(h, state.mem, state.memSize)

        val digest = ByteArray(4)
        encodeBeInt(h, digest, 0)

        reset()

        return digest
    }

    override val digestLength: Int
        get() = 4

    override fun reset() {
        state = State32()

        state.v1 = seed + prime1 + prime2
        state.v2 = seed + prime2
        state.v3 = seed + 0
        state.v4 = seed - prime1
    }

    override fun copy(): XxHash32Hasher {
        return XxHash32Hasher(seed).also {
            it.state = State32().apply {
                totalLen = state.totalLen
                largeLen = state.largeLen
                v1 = state.v1
                v2 = state.v2
                v3 = state.v3
                v4 = state.v4
                mem = state.mem.copyOf()
                memSize = state.memSize
            }
        }
    }

    override fun toString() = "XXH32"

    companion object {
        const val prime1: Int = 2654435761.toInt()
        const val prime2: Int = 2246822519.toInt()
        const val prime3: Int = 3266489917.toInt()
        const val prime4: Int = 668265263
        const val prime5: Int = 374761393
    }

    internal class State32 {
        var totalLen: Int = 0
        var largeLen: Boolean = false
        var v1: Int = 0
        var v2: Int = 0
        var v3: Int = 0
        var v4: Int = 0
        var mem: ByteArray = ByteArray(4 * 4)
        var memSize: Int = 0
    }
}
