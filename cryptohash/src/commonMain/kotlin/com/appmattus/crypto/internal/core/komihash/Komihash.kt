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

package com.appmattus.crypto.internal.core.komihash

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalDigest
import com.appmattus.crypto.internal.core.decodeLEUInt
import com.appmattus.crypto.internal.core.decodeLEULong
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.multiplyHigh

/**
 * [komihash](https://github.com/avaneev/komihash) version 5
 */
internal class Komihash(private val seed: ULong) : NonIncrementalDigest<Komihash>() {

    private var hash: ULong = 0u

    override val digestLength: Int
        get() = 8

    override val blockLength: Int
        get() = 64

    override fun process(input: ByteBuffer) {
        val state = State(seed)
        hash = if (input.size < 32) state.hashShort(input) else state.hashLong(input)
    }

    /**
     * The two 64-bit seeds that are mixed through the message, named after Seed1 and Seed5 in the reference code
     */
    private class State(useSeed: ULong) {
        var seed1: ULong = IVAL1 xor (useSeed and VAL01)
        var seed5: ULong = IVAL5 xor (useSeed and VAL10)

        init {
            round()
        }

        // kh_m128(u, v, &Seed1, &Seed5): Seed1 = low(u * v), Seed5 += high(u * v)
        fun multiply(u: ULong, v: ULong) {
            seed1 = u * v
            seed5 += multiplyHigh(u, v)
        }

        fun round() {
            multiply(seed1, seed5)
            seed1 = seed1 xor seed5
        }

        fun hash16(input: ByteBuffer, offset: Int) {
            multiply(input.decodeLEULong(offset) xor seed1, input.decodeLEULong(offset + 8) xor seed5)
            seed1 = seed1 xor seed5
        }

        fun finish(r1h: ULong, r2h: ULong): ULong {
            multiply(r1h, r2h)
            seed1 = seed1 xor seed5
            round()
            return seed1
        }

        // Messages shorter than 32 bytes
        @Suppress("CyclomaticComplexMethod", "NestedBlockDepth")
        fun hashShort(input: ByteBuffer): ULong {
            val len = input.size
            var r1h = seed1
            var r2h = seed5

            if (len >= 16) {
                hash16(input, 0)
                return tail(input, 16, len - 16)
            }

            if (len > 7) {
                r1h = r1h xor input.decodeLEULong(0)
                if (len < 12) {
                    val ml8 = (len * 8) xor 88
                    val m = input.byteAt(len - 3) or (input.byteAt(len - 1) shl 16) or (1uL shl 24) or (input.byteAt(len - 2) shl 8)
                    r2h = r2h xor (m shr ml8)
                } else {
                    val mhs = 128 - len * 8
                    val mh = (input.decodeLEUInt(len - 4).toULong() or (1uL shl 32)) shr mhs
                    val ml = input.decodeLEUInt(8).toULong()
                    r2h = r2h xor ((mh shl 32) or ml)
                }
            } else if (len != 0) {
                if (len < 4) {
                    r1h = r1h xor input.byteAt(0) xor (1uL shl (len * 8))
                    if (len != 1) {
                        r1h = r1h xor (input.byteAt(1) shl 8)
                        if (len != 2) {
                            r1h = r1h xor (input.byteAt(2) shl 16)
                        }
                    }
                } else {
                    val mhs = 64 - len * 8
                    val mh = (input.decodeLEUInt(len - 4).toULong() or (1uL shl 32)) shr mhs
                    val ml = input.decodeLEUInt(0).toULong()
                    r1h = r1h xor ((mh shl 32) or ml)
                }
            }

            return finish(r1h, r2h)
        }

        // Messages of 32 bytes or more
        fun hashLong(input: ByteBuffer): ULong {
            var offset = 0
            var remaining = input.size

            if (remaining > 63) {
                var seed2 = IVAL2 xor seed1
                var seed3 = IVAL3 xor seed1
                var seed4 = IVAL4 xor seed1
                var seed6 = IVAL6 xor seed5
                var seed7 = IVAL7 xor seed5
                var seed8 = IVAL8 xor seed5

                do {
                    val u1 = input.decodeLEULong(offset) xor seed1
                    val v1 = input.decodeLEULong(offset + 32) xor seed5
                    val u2 = input.decodeLEULong(offset + 8) xor seed2
                    val v2 = input.decodeLEULong(offset + 40) xor seed6
                    val u3 = input.decodeLEULong(offset + 16) xor seed3
                    val v3 = input.decodeLEULong(offset + 48) xor seed7
                    val u4 = input.decodeLEULong(offset + 24) xor seed4
                    val v4 = input.decodeLEULong(offset + 56) xor seed8

                    seed1 = u1 * v1
                    seed5 += multiplyHigh(u1, v1)
                    seed2 = u2 * v2
                    seed6 += multiplyHigh(u2, v2)
                    seed3 = u3 * v3
                    seed7 += multiplyHigh(u3, v3)
                    seed4 = u4 * v4
                    seed8 += multiplyHigh(u4, v4)

                    offset += 64
                    remaining -= 64

                    seed4 = seed4 xor seed7
                    seed1 = seed1 xor seed8
                    seed2 = seed2 xor seed5
                    seed3 = seed3 xor seed6
                } while (remaining > 63)

                seed5 = seed5 xor seed6 xor seed7 xor seed8
                seed1 = seed1 xor seed2 xor seed3 xor seed4
            }

            if (remaining > 31) {
                hash16(input, offset)
                hash16(input, offset + 16)
                offset += 32
                remaining -= 32
            }

            if (remaining > 15) {
                hash16(input, offset)
                offset += 16
                remaining -= 16
            }

            return tail(input, offset, remaining)
        }

        // The final 0 to 15 bytes, which may be read together with earlier bytes of the message
        private fun tail(input: ByteBuffer, offset: Int, remaining: Int): ULong {
            val last = (input.decodeLEULong(offset + remaining - 8) shr 8) or (1uL shl 56)
            return if (remaining < 8) {
                finish((last shr ((remaining * 8) xor 56)) xor seed1, seed5)
            } else {
                finish(input.decodeLEULong(offset) xor seed1, (last shr ((remaining * 8) xor 120)) xor seed5)
            }
        }

        private fun ByteBuffer.byteAt(index: Int): ULong = get(index).toULong() and 0xffu
    }

    override fun result(): ByteArray {
        val digest = ByteArray(digestLength)
        encodeBELong(hash.toLong(), digest, 0)

        return digest
    }

    override fun copy(): Komihash {
        return copyState(
            Komihash(seed).apply {
                hash = this@Komihash.hash
            }
        )
    }

    override fun toString(): String = "komihash"

    private companion object {
        private const val IVAL1: ULong = 0x243F6A8885A308D3u
        private const val IVAL2: ULong = 0x13198A2E03707344u
        private const val IVAL3: ULong = 0xA4093822299F31D0u
        private const val IVAL4: ULong = 0x082EFA98EC4E6C89u
        private const val IVAL5: ULong = 0x452821E638D01377u
        private const val IVAL6: ULong = 0xBE5466CF34E90C6Cu
        private const val IVAL7: ULong = 0xC0AC29B7C97C50DDu
        private const val IVAL8: ULong = 0x3F84D5B5B5470917u
        private const val VAL01: ULong = 0x5555555555555555u
        private const val VAL10: ULong = 0xAAAAAAAAAAAAAAAAu
    }
}
