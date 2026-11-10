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

/*
 * Kotlin/JS stores a Long as an object holding two 32-bit halves, so every Long operation allocates a new one. Engines
 * without a JIT to optimise those allocations away, such as Hermes, are particularly slow at it.
 *
 * This holds each of the four 64-bit words as a pair of Ints instead, high and low, for the whole life of the state.
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING", "MagicNumber")
internal actual class SipHashState actual constructor() {
    private var v0h = 0
    private var v0l = 0
    private var v1h = 0
    private var v1l = 0
    private var v2h = 0
    private var v2l = 0
    private var v3h = 0
    private var v3l = 0

    actual fun reset(k0: Long, k1: Long, wide: Boolean) {
        val k0h = (k0 ushr 32).toInt()
        val k0l = k0.toInt()
        val k1h = (k1 ushr 32).toInt()
        val k1l = k1.toInt()
        // "somepseudorandomlygeneratedbytes"
        v0h = k0h xor 0x736f6d65
        v0l = k0l xor 0x70736575
        v1h = k1h xor 0x646f7261
        v1l = k1l xor 0x6e646f6d
        v2h = k0h xor 0x6c796765
        v2l = k0l xor 0x6e657261
        v3h = k1h xor 0x74656462
        v3l = k1l xor 0x79746573
        if (wide) v1l = v1l xor 0xee
    }

    actual fun copyFrom(other: SipHashState) {
        v0h = other.v0h
        v0l = other.v0l
        v1h = other.v1h
        v1l = other.v1l
        v2h = other.v2h
        v2l = other.v2l
        v3h = other.v3h
        v3l = other.v3l
    }

    actual fun compress(input: ByteArray, offset: Int, words: Int, rounds: Int) {
        var pos = offset
        repeat(words) {
            processWord(readIntLE(input, pos + 4), readIntLE(input, pos), rounds)
            pos += 8
        }
    }

    @Suppress("LongParameterList")
    actual fun finish(
        buffer: ByteArray,
        length: Int,
        totalLength: Int,
        compressionRounds: Int,
        finalizationRounds: Int,
        output: ByteArray
    ) {
        // The remaining bytes, little-endian, with the low byte of the total length in the top byte
        var h = (totalLength and 0xff) shl 24
        var l = 0
        for (i in 0 until length) {
            val b = buffer[i].toInt() and 0xff
            if (i < 4) l = l or (b shl (i shl 3)) else h = h or (b shl ((i - 4) shl 3))
        }
        processWord(h, l, compressionRounds)

        if (output.size == 8) {
            v2l = v2l xor 0xff
            sipRounds(finalizationRounds)
            writeTag(output, 0)
        } else {
            v2l = v2l xor 0xee
            sipRounds(finalizationRounds)
            writeTag(output, 0)
            v1l = v1l xor 0xdd
            sipRounds(finalizationRounds)
            writeTag(output, 8)
        }
    }

    /** Writes v0 ^ v1 ^ v2 ^ v3 to [output] at [offset] in little-endian order */
    private fun writeTag(output: ByteArray, offset: Int) {
        val h = v0h xor v1h xor v2h xor v3h
        val l = v0l xor v1l xor v2l xor v3l
        for (i in 0..3) {
            output[offset + i] = (l ushr (i shl 3)).toByte()
            output[offset + 4 + i] = (h ushr (i shl 3)).toByte()
        }
    }

    private fun processWord(mh: Int, ml: Int, rounds: Int) {
        v3h = v3h xor mh
        v3l = v3l xor ml
        sipRounds(rounds)
        v0h = v0h xor mh
        v0l = v0l xor ml
    }

    @Suppress("LongMethod")
    private fun sipRounds(rounds: Int) {
        var v0h = v0h
        var v0l = v0l
        var v1h = v1h
        var v1l = v1l
        var v2h = v2h
        var v2l = v2l
        var v3h = v3h
        var v3l = v3l
        repeat(rounds) {
            // v0 += v1, v2 += v3
            var l = v0l + v1l
            v0h += v1h + carry(l, v1l)
            v0l = l
            l = v2l + v3l
            v2h += v3h + carry(l, v3l)
            v2l = l
            // v1 = rotl(v1, 13), v3 = rotl(v3, 16)
            var h = (v1h shl 13) or (v1l ushr 19)
            v1l = (v1l shl 13) or (v1h ushr 19)
            v1h = h
            h = (v3h shl 16) or (v3l ushr 16)
            v3l = (v3l shl 16) or (v3h ushr 16)
            v3h = h
            // v1 ^= v0, v3 ^= v2
            v1h = v1h xor v0h
            v1l = v1l xor v0l
            v3h = v3h xor v2h
            v3l = v3l xor v2l
            // v0 = rotl(v0, 32)
            h = v0h
            v0h = v0l
            v0l = h
            // v2 += v1, v0 += v3
            l = v2l + v1l
            v2h += v1h + carry(l, v1l)
            v2l = l
            l = v0l + v3l
            v0h += v3h + carry(l, v3l)
            v0l = l
            // v1 = rotl(v1, 17), v3 = rotl(v3, 21)
            h = (v1h shl 17) or (v1l ushr 15)
            v1l = (v1l shl 17) or (v1h ushr 15)
            v1h = h
            h = (v3h shl 21) or (v3l ushr 11)
            v3l = (v3l shl 21) or (v3h ushr 11)
            v3h = h
            // v1 ^= v2, v3 ^= v0
            v1h = v1h xor v2h
            v1l = v1l xor v2l
            v3h = v3h xor v0h
            v3l = v3l xor v0l
            // v2 = rotl(v2, 32)
            h = v2h
            v2h = v2l
            v2l = h
        }
        this.v0h = v0h
        this.v0l = v0l
        this.v1h = v1h
        this.v1l = v1l
        this.v2h = v2h
        this.v2l = v2l
        this.v3h = v3h
        this.v3l = v3l
    }
}
