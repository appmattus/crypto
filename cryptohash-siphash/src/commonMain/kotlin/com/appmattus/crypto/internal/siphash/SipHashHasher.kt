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

package com.appmattus.crypto.internal.siphash

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.AbstractHasher
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong
import com.appmattus.crypto.internal.core.rotateLeft

/**
 * [SipHashHasher](https://www.aumasson.jp/siphash/siphash.pdf) with [compressionRounds] compression and [finalizationRounds]
 * finalization rounds, producing a 64-bit tag or, with [outputBits] of 128, the 128-bit SipHash128 variant.
 *
 * Tags are output in little-endian byte order, matching the reference implementation's test vectors.
 */
internal class SipHashHasher private constructor(
    private val k0: Long,
    private val k1: Long,
    private val compressionRounds: Int,
    private val finalizationRounds: Int,
    private val outputBits: Int
) : AbstractHasher() {

    constructor(key: ByteArray, compressionRounds: Int, finalizationRounds: Int, outputBits: Int) : this(
        decodeLELong(key, 0),
        decodeLELong(key, 8),
        compressionRounds,
        finalizationRounds,
        outputBits
    )

    private val state = SipHashState()

    private val buffer = ByteArray(WORD_BYTES)
    private var bufferPos = 0

    // Only the low byte of the total length is used, so it's counted in an Int, which wraps harmlessly
    private var totalLength = 0

    init {
        reset()
    }

    override fun update(input: ByteArray, offset: Int, length: Int): Hasher {
        var pos = offset
        val end = offset + length
        totalLength += length

        if (bufferPos > 0) {
            while (bufferPos < WORD_BYTES && pos < end) buffer[bufferPos++] = input[pos++]
            if (bufferPos < WORD_BYTES) return this
            state.compress(buffer, 0, 1, compressionRounds)
            bufferPos = 0
        }

        val words = (end - pos) / WORD_BYTES
        if (words > 0) {
            state.compress(input, pos, words, compressionRounds)
            pos += words * WORD_BYTES
        }

        while (pos < end) buffer[bufferPos++] = input[pos++]
        return this
    }

    override fun digest(): ByteArray {
        val output = ByteArray(digestLength)
        state.finish(buffer, bufferPos, totalLength, compressionRounds, finalizationRounds, output)
        reset()
        return output
    }

    override val digestLength: Int
        get() = outputBits / 8

    override fun reset() {
        state.reset(k0, k1, outputBits == 128)
        buffer.fill(0)
        bufferPos = 0
        totalLength = 0
    }

    override fun copy(): SipHashHasher = SipHashHasher(k0, k1, compressionRounds, finalizationRounds, outputBits).also {
        it.state.copyFrom(state)
        buffer.copyInto(it.buffer)
        it.bufferPos = bufferPos
        it.totalLength = totalLength
    }

    override fun toString(): String {
        val prefix = if (outputBits == 64) "SipHash" else "SipHash128"
        return "$prefix-$compressionRounds-$finalizationRounds"
    }

    private companion object {
        const val WORD_BYTES = 8
    }
}

/**
 * The four-word SipHash state, with the operations [SipHashHasher] makes on it.
 *
 * Kotlin/JS has its own implementation holding each word as a pair of Ints, as its [Long] is an object and allocates
 * on every operation. The other platforms use [SipHashStateLong].
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
internal expect class SipHashState() {
    /** Initialises the state from the key words [k0] and [k1], for the 128-bit output variant when [wide] */
    fun reset(k0: Long, k1: Long, wide: Boolean)

    /** Sets the state to a copy of [other] */
    fun copyFrom(other: SipHashState)

    /** Compresses [words] 8-byte little-endian words of [input] from [offset], each with [rounds] SipRounds */
    fun compress(input: ByteArray, offset: Int, words: Int, rounds: Int)

    /**
     * Compresses the final word, the first [length] bytes of [buffer] with the low byte of [totalLength] on top, then
     * finalises with [finalizationRounds] SipRounds and writes the 8 or 16-byte tag to [output] in little-endian order
     */
    @Suppress("LongParameterList")
    fun finish(
        buffer: ByteArray,
        length: Int,
        totalLength: Int,
        compressionRounds: Int,
        finalizationRounds: Int,
        output: ByteArray
    )
}

/**
 * The [Long] implementation of [SipHashState], for platforms whose [Long] is a 64-bit machine integer
 */
internal class SipHashStateLong {
    private var v0 = 0L
    private var v1 = 0L
    private var v2 = 0L
    private var v3 = 0L

    fun reset(k0: Long, k1: Long, wide: Boolean) {
        v0 = k0 xor 0x736f6d6570736575L
        v1 = k1 xor 0x646f72616e646f6dL
        v2 = k0 xor 0x6c7967656e657261L
        v3 = k1 xor 0x7465646279746573L
        if (wide) v1 = v1 xor 0xee
    }

    fun copyFrom(other: SipHashStateLong) {
        v0 = other.v0
        v1 = other.v1
        v2 = other.v2
        v3 = other.v3
    }

    fun compress(input: ByteArray, offset: Int, words: Int, rounds: Int) {
        var pos = offset
        repeat(words) {
            processWord(decodeLELong(input, pos), rounds)
            pos += 8
        }
    }

    @Suppress("LongParameterList")
    fun finish(
        buffer: ByteArray,
        length: Int,
        totalLength: Int,
        compressionRounds: Int,
        finalizationRounds: Int,
        output: ByteArray
    ) {
        var last = (totalLength.toLong() and 0xff) shl 56
        for (i in 0 until length) last = last or ((buffer[i].toLong() and 0xff) shl (i * 8))
        processWord(last, compressionRounds)

        if (output.size == 8) {
            v2 = v2 xor 0xff
            sipRounds(finalizationRounds)
            encodeLELong(v0 xor v1 xor v2 xor v3, output, 0)
        } else {
            v2 = v2 xor 0xee
            sipRounds(finalizationRounds)
            encodeLELong(v0 xor v1 xor v2 xor v3, output, 0)
            v1 = v1 xor 0xdd
            sipRounds(finalizationRounds)
            encodeLELong(v0 xor v1 xor v2 xor v3, output, 8)
        }
    }

    private fun processWord(m: Long, rounds: Int) {
        v3 = v3 xor m
        sipRounds(rounds)
        v0 = v0 xor m
    }

    private fun sipRounds(rounds: Int) {
        repeat(rounds) {
            v0 += v1
            v2 += v3
            v1 = v1.rotateLeft(13)
            v3 = v3.rotateLeft(16)
            v1 = v1 xor v0
            v3 = v3 xor v2
            v0 = v0.rotateLeft(32)
            v2 += v1
            v0 += v3
            v1 = v1.rotateLeft(17)
            v3 = v3.rotateLeft(21)
            v1 = v1 xor v2
            v3 = v3 xor v0
            v2 = v2.rotateLeft(32)
        }
    }
}
