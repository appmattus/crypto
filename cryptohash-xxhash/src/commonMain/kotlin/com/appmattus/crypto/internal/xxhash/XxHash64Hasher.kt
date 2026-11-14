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
import com.appmattus.crypto.internal.core.encodeBeLong

/**
 * @property seed A seed for generate digest. Default is 0.
 */
@Suppress("TooManyFunctions")
internal class XxHash64Hasher(private val seed: Long = 0) : AbstractHasher() {

    private var state = State64()

    init {
        reset()
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        var index = 0

        countBytes(length)

        if (state.memSize + length < 32) {
            // fill in tmp buffer
            copyBytes(input, index + offset, state.mem, state.memSize, length)
            state.memSize += length

            return this
        }

        if (state.memSize > 0) {
            // some data left from previous update
            copyBytes(input, index + offset, state.mem, state.memSize, 32 - state.memSize)

            xxh64Stripes(state, state.mem, 0, 1)

            index += 32 - state.memSize
            state.memSize = 0
        }

        if (index <= length - 32) {
            val stripes = (length - index) / 32
            xxh64Stripes(state, input, index + offset, stripes)
            index += stripes * 32
        }

        if (index < length) {
            copyBytes(input, index + offset, state.mem, 0, length - index)

            state.memSize = length - index
        }
        return this
    }

    override fun update(input: Byte): Hasher {
        // Buffer a single byte directly unless it completes a stripe
        if (state.memSize < 31) {
            state.mem[state.memSize++] = input
            countBytes(1)
            return this
        }
        return super.update(input)
    }

    /**
     * Adds [length] to the total length. Lengths gather in the Int pendingLen rather than the Long totalLen, as each Long
     * addition allocates on Kotlin/JS, and fold into totalLen before it could overflow.
     */
    private fun countBytes(length: Int) {
        val pending = state.pendingLen + length
        if (pending in 0 until PENDING_LIMIT) {
            state.pendingLen = pending
        } else {
            state.totalLen += state.pendingLen.toLong() + length
            state.pendingLen = 0
        }
    }

    override fun digest(): ByteArray {
        state.totalLen += state.pendingLen
        state.pendingLen = 0
        val h = xxh64Finish(state)

        reset()

        val digest = ByteArray(8)
        encodeBeLong(h, digest, 0)
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

    override fun copy(): XxHash64Hasher {
        return XxHash64Hasher(seed).also {
            it.state = State64().apply {
                totalLen = state.totalLen
                pendingLen = state.pendingLen
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

    override fun toString() = "XXH64"

    companion object {
        const val prime1: Long = -7046029288634856825
        const val prime2: Long = -4417276706812531889
        const val prime3: Long = 1609587929392839161
        const val prime4: Long = -8796714831421723037
        const val prime5: Long = 2870177450012600261

        // Fold pendingLen into totalLen before it reaches this, well short of overflowing
        private const val PENDING_LIMIT = 1 shl 30
    }

    internal class State64 {
        var totalLen: Long = 0

        // Bytes counted but not yet added to totalLen
        var pendingLen: Int = 0
        var largeLen: Boolean = false
        var v1: Long = 0
        var v2: Long = 0
        var v3: Long = 0
        var v4: Long = 0
        var mem: ByteArray = ByteArray(8 * 4)
        var memSize: Int = 0
    }
}
