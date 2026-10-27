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

package com.appmattus.crypto.internal.core

/**
 * [SipHash](https://www.aumasson.jp/siphash/siphash.pdf) with [compressionRounds] compression and [finalizationRounds]
 * finalization rounds, producing a 64-bit tag or, with [outputBits] of 128, the 128-bit SipHash128 variant.
 *
 * Tags are output in little-endian byte order, matching the reference implementation's test vectors.
 */
internal class SipHash private constructor(
    private val k0: Long,
    private val k1: Long,
    private val compressionRounds: Int,
    private val finalizationRounds: Int,
    private val outputBits: Int
) : AbstractDigest<SipHash>() {

    constructor(key: ByteArray, compressionRounds: Int, finalizationRounds: Int, outputBits: Int) : this(
        decodeLELong(key, 0),
        decodeLELong(key, 8),
        compressionRounds,
        finalizationRounds,
        outputBits
    )

    private var v0 = 0L
    private var v1 = 0L
    private var v2 = 0L
    private var v3 = 0L

    private val buffer = ByteArray(WORD_BYTES)
    private var bufferPos = 0
    private var totalLength = 0L

    init {
        reset()
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var pos = offset
        val end = offset + length
        totalLength += length

        if (bufferPos > 0) {
            while (bufferPos < WORD_BYTES && pos < end) buffer[bufferPos++] = input[pos++]
            if (bufferPos < WORD_BYTES) return
            processWord(decodeLELong(buffer, 0))
            bufferPos = 0
        }

        while (end - pos >= WORD_BYTES) {
            processWord(decodeLELong(input, pos))
            pos += WORD_BYTES
        }

        while (pos < end) buffer[bufferPos++] = input[pos++]
    }

    override fun digest(): ByteArray {
        var last = (totalLength and 0xff) shl 56
        for (i in 0 until bufferPos) last = last or ((buffer[i].toLong() and 0xff) shl (i * 8))
        processWord(last)

        val output = ByteArray(digestLength)
        if (outputBits == 64) {
            v2 = v2 xor 0xff
            sipRounds(finalizationRounds)
            encodeLELong(v0 xor v1 xor v2 xor v3, output, 0)
        } else {
            v2 = v2 xor 0xee
            sipRounds(finalizationRounds)
            encodeLELong(v0 xor v1 xor v2 xor v3, output, 0)
            v1 = v1 xor 0xdd
            sipRounds(finalizationRounds)
            encodeLELong(v0 xor v1 xor v2 xor v3, output, WORD_BYTES)
        }

        reset()
        return output
    }

    override val digestLength: Int
        get() = outputBits / 8

    override fun reset() {
        v0 = k0 xor 0x736f6d6570736575L
        v1 = k1 xor 0x646f72616e646f6dL
        v2 = k0 xor 0x6c7967656e657261L
        v3 = k1 xor 0x7465646279746573L
        if (outputBits == 128) v1 = v1 xor 0xee
        buffer.fill(0)
        bufferPos = 0
        totalLength = 0
    }

    override fun copy(): SipHash = SipHash(k0, k1, compressionRounds, finalizationRounds, outputBits).also {
        it.v0 = v0
        it.v1 = v1
        it.v2 = v2
        it.v3 = v3
        buffer.copyInto(it.buffer)
        it.bufferPos = bufferPos
        it.totalLength = totalLength
    }

    override val blockLength: Int
        get() = WORD_BYTES

    override fun toString(): String {
        val prefix = if (outputBits == 64) "SipHash" else "SipHash128"
        return "$prefix-$compressionRounds-$finalizationRounds"
    }

    private fun processWord(m: Long) {
        v3 = v3 xor m
        sipRounds(compressionRounds)
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

    private companion object {
        const val WORD_BYTES = 8
    }
}
