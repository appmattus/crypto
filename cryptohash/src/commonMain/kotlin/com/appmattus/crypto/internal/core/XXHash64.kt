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

/**
 * @property seed A seed for generate digest. Default is 0.
 */
internal class XXHash64(private val seed: Long = 0) : AbstractDigest<XXHash64>() {

    private var state = State64()

    init {
        reset()
    }

    private fun round(seed: Long, input: Long): Long {
        var seed2 = seed
        seed2 += input * prime2
        seed2 = circularLeftLong(seed2, 31)
        seed2 *= prime1

        return seed2
    }

    private fun mergeRound(acc: Long, value: Long): Long {
        val val2 = round(0, value)
        var acc2 = acc xor val2
        acc2 = acc2 * prime1 + prime4

        return acc2
    }

    private fun avalanche(h: Long): Long {
        var h2 = h
        h2 = h2 xor (h2 ushr 33)
        h2 *= prime2
        h2 = h2 xor (h2 ushr 29)
        h2 *= prime3
        h2 = h2 xor (h2 ushr 32)
        return h2
    }

    private fun finalize(h: Long, array: ByteArray, len: Int): Long {
        var index = 0
        var h2 = h

        fun process1() {
            h2 = h2 xor (array[index].toLong() and 0xff) * prime5
            index += 1
            h2 = circularLeftLong(h2, 11) * prime1
        }

        fun process4() {
            h2 = h2 xor ((decodeLEInt(array, index).toLong() and 0xFFFFFFFFL) * prime1)
            index += 4
            h2 = circularLeftLong(h2, 23) * prime2 + prime3
        }

        fun process8() {
            val k1 = round(0, decodeLELong(array, index))
            index += 8
            h2 = h2 xor k1
            h2 = circularLeftLong(h2, 27) * prime1 + prime4
        }

        val x = len and 31

        repeat(x shr 3) { process8() }
        repeat(x and 7 shr 2) { process4() }
        repeat(x and 3) { process1() }

        return avalanche(h2)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var index = 0

        state.totalLen += length

        if (state.memSize + length < 32) {

            // fill in tmp buffer
            input.copyInto(state.mem, state.memSize, index + offset, index + offset + length)
            state.memSize += length

            return
        }

        if (state.memSize > 0) {
            // some data left from previous update
            input.copyInto(state.mem, state.memSize, index + offset, index + offset + (32 - state.memSize))

            state.v1 = round(state.v1, decodeLELong(state.mem, 0))
            state.v2 = round(state.v2, decodeLELong(state.mem, 8))
            state.v3 = round(state.v3, decodeLELong(state.mem, 16))
            state.v4 = round(state.v4, decodeLELong(state.mem, 24))

            index += 32 - state.memSize
            state.memSize = 0
        }

        if (index <= length - 32) {

            val limit = length - 32

            do {
                state.v1 = round(state.v1, decodeLELong(input, index + offset))
                index += 8

                state.v2 = round(state.v2, decodeLELong(input, index + offset))
                index += 8

                state.v3 = round(state.v3, decodeLELong(input, index + offset))
                index += 8

                state.v4 = round(state.v4, decodeLELong(input, index + offset))
                index += 8
            } while (index <= limit)
        }

        if (index < length) {
            input.copyInto(state.mem, 0, index + offset, index + offset + (length - index))

            state.memSize = length - index
        }
    }

    override fun digest(): ByteArray {
        var h: Long

        if (state.totalLen >= 32) {
            h = circularLeftLong(state.v1, 1) +
                    circularLeftLong(state.v2, 7) +
                    circularLeftLong(state.v3, 12) +
                    circularLeftLong(state.v4, 18)

            h = mergeRound(h, state.v1)
            h = mergeRound(h, state.v2)
            h = mergeRound(h, state.v3)
            h = mergeRound(h, state.v4)
        } else {
            h = state.v3 /* == seed */ + prime5
        }

        h += state.totalLen

        h = finalize(h, state.mem, state.memSize)

        reset()

        val digest = ByteArray(8)
        encodeBELong(h, digest, 0)
        return digest
    }

    override val digestLength: Int
        get() = 8

    override fun reset() {
        state = State64()

        state.v1 = seed + prime1 + prime2
        state.v2 = seed + prime2
        state.v3 = seed + 0
        state.v4 = seed - prime1
    }

    override fun copy(): XXHash64 {
        return XXHash64(seed).also {
            it.state = State64().apply {
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

    override val blockLength: Int
        get() = 32

    override fun toString() = "XXH64"

    companion object {
        const val prime1: Long = -7046029288634856825
        const val prime2: Long = -4417276706812531889
        const val prime3: Long = 1609587929392839161
        const val prime4: Long = -8796714831421723037
        const val prime5: Long = 2870177450012600261
    }

    internal class State64 {
        var totalLen: Long = 0
        var largeLen: Boolean = false
        var v1: Long = 0
        var v2: Long = 0
        var v3: Long = 0
        var v4: Long = 0
        var mem: ByteArray = ByteArray(8 * 4)
        var memSize: Int = 0
    }
}
