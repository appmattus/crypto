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

package com.appmattus.crypto.internal.core.bouncycastle

import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.circularRightLong
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLEInt
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * Reference implementation of national ukrainian standard of hashing transformation DSTU7564.
 * Thanks to Roman Oliynykov' native C implementation:
 * https://github.com/Roman-Oliynykov/Kupyna-reference
 */
@Suppress("TooManyFunctions", "MagicNumber", "LargeClass")
internal class DSTU7564 : Digest<DSTU7564> {
    override var digestLength = 0
        private set
    private var byteLength = 0
    private var columns = 0
    private var rounds = 0
    private lateinit var state: LongArray
    private lateinit var tempState1: LongArray
    private lateinit var tempState2: LongArray

    // TODO Guard against 'inputBlocks' overflow (2^64 blocks)
    private var inputBlocks: Long = 0
    private var bufOff = 0
    private lateinit var buf: ByteArray

    constructor(digest: DSTU7564) {
        copyIn(digest)
    }

    private fun copyIn(digest: DSTU7564) {
        digestLength = digest.digestLength
        byteLength = digest.byteLength
        rounds = digest.rounds
        if (columns > 0 && columns == digest.columns) {
            digest.state.copyInto(state, 0, 0, columns)
            digest.buf.copyInto(buf, 0, 0, byteLength)
        } else {
            columns = digest.columns
            state = digest.state.copyOf()
            tempState1 = LongArray(columns)
            tempState2 = LongArray(columns)
            buf = digest.buf.copyOf()
        }
        inputBlocks = digest.inputBlocks
        bufOff = digest.bufOff
    }

    constructor(hashSizeBits: Int) {
        if (hashSizeBits == 256 || hashSizeBits == 384 || hashSizeBits == 512) {
            digestLength = hashSizeBits ushr 3
        } else {
            throw IllegalArgumentException("Hash size is not recommended. Use 256/384/512 instead")
        }
        if (hashSizeBits > 256) {
            columns = NB_1024
            rounds = NR_1024
        } else {
            columns = NB_512
            rounds = NR_512
        }
        byteLength = columns shl 3
        state = LongArray(columns)
        state[0] = byteLength.toLong()
        tempState1 = LongArray(columns)
        tempState2 = LongArray(columns)
        buf = ByteArray(byteLength)
    }

    override fun update(input: Byte) {
        buf[bufOff++] = input
        if (bufOff == byteLength) {
            processBlock(buf, 0)
            bufOff = 0
            ++inputBlocks
        }
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var inOff = offset
        var len = length
        while (bufOff != 0 && len > 0) {
            update(input[inOff++])
            --len
        }
        if (len > 0) {
            while (len >= byteLength) {
                processBlock(input, inOff)
                inOff += byteLength
                len -= byteLength
                ++inputBlocks
            }
            while (len > 0) {
                update(input[inOff++])
                --len
            }
        }
    }

    @Suppress("NAME_SHADOWING")
    fun doFinal(out: ByteArray?, outOff: Int): Int {
        // Apply padding: terminator byte and 96-bit length field
        var outOff = outOff
        run {
            val inputBytes = bufOff
            buf[bufOff++] = 0x80.toByte()
            val lenPos = this.byteLength - 12
            if (bufOff > lenPos) {
                while (bufOff < this.byteLength) {
                    buf[bufOff++] = 0
                }
                bufOff = 0
                processBlock(buf, 0)
            }
            while (bufOff < lenPos) {
                buf[bufOff++] = 0
            }
            var c = (inputBlocks and 0xFFFFFFFFL) * this.byteLength + inputBytes shl 3
            encodeLEInt(c.toInt(), buf, bufOff)
            bufOff += 4
            c = c ushr 32
            c += (inputBlocks ushr 32) * this.byteLength shl 3
            encodeLELong(c, buf, bufOff)
            //            bufOff += 8;
            processBlock(buf, 0)
        }
        run {
            state.copyInto(tempState1, 0, 0, columns)
            p(tempState1)
            for (col in 0 until columns) {
                state[col] = state[col] xor tempState1[col]
            }
        }
        val neededColumns = digestLength ushr 3
        for (col in columns - neededColumns until columns) {
            encodeLELong(state[col], out!!, outOff)
            outOff += 8
        }
        reset()
        return digestLength
    }

    override fun reset() {
        state.fill(0L)
        state[0] = byteLength.toLong()
        inputBlocks = 0
        bufOff = 0
    }

    private fun processBlock(input: ByteArray, inOff: Int) {
        var pos = inOff
        for (col in 0 until columns) {
            val word: Long = decodeLELong(input, pos)
            pos += 8
            tempState1[col] = state[col] xor word
            tempState2[col] = word
        }
        p(tempState1)
        q(tempState2)
        for (col in 0 until columns) {
            state[col] = state[col] xor (tempState1[col] xor tempState2[col])
        }
    }

    private fun p(s: LongArray) {
        for (round in 0 until rounds) {
            var rc = round.toLong()

            /* AddRoundConstants */
            for (col in 0 until columns) {
                s[col] = s[col] xor rc
                rc += 0x10L
            }
            shiftRows(s)
            subBytes(s)
            mixColumns(s)
        }
    }

    private fun q(s: LongArray) {
        for (round in 0 until rounds) {
            /* AddRoundConstantsQ */
            var rc = (columns - 1 shl 4 xor round).toLong() shl 56 or 0x00F0F0F0F0F0F0F3L
            for (col in 0 until columns) {
                s[col] += rc
                rc -= 0x1000000000000000L
            }
            shiftRows(s)
            subBytes(s)
            mixColumns(s)
        }
    }

    private fun mixColumns(s: LongArray) {
        for (col in 0 until columns) {
            s[col] = mixColumn(s[col])
        }
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    private fun shiftRows(s: LongArray) {
        when (columns) {
            NB_512 -> {
                var c0 = s[0]
                var c1 = s[1]
                var c2 = s[2]
                var c3 = s[3]
                var c4 = s[4]
                var c5 = s[5]
                var c6 = s[6]
                var c7 = s[7]
                var d: Long
                d = c0 xor c4 and -0x100000000L
                c0 = c0 xor d
                c4 = c4 xor d
                d = c1 xor c5 and 0x00FFFFFFFF000000L
                c1 = c1 xor d
                c5 = c5 xor d
                d = c2 xor c6 and 0x0000FFFFFFFF0000L
                c2 = c2 xor d
                c6 = c6 xor d
                d = c3 xor c7 and 0x000000FFFFFFFF00L
                c3 = c3 xor d
                c7 = c7 xor d
                d = c0 xor c2 and -0xffff00010000L
                c0 = c0 xor d
                c2 = c2 xor d
                d = c1 xor c3 and 0x00FFFF0000FFFF00L
                c1 = c1 xor d
                c3 = c3 xor d
                d = c4 xor c6 and -0xffff00010000L
                c4 = c4 xor d
                c6 = c6 xor d
                d = c5 xor c7 and 0x00FFFF0000FFFF00L
                c5 = c5 xor d
                c7 = c7 xor d
                d = c0 xor c1 and -0xff00ff00ff0100L
                c0 = c0 xor d
                c1 = c1 xor d
                d = c2 xor c3 and -0xff00ff00ff0100L
                c2 = c2 xor d
                c3 = c3 xor d
                d = c4 xor c5 and -0xff00ff00ff0100L
                c4 = c4 xor d
                c5 = c5 xor d
                d = c6 xor c7 and -0xff00ff00ff0100L
                c6 = c6 xor d
                c7 = c7 xor d
                s[0] = c0
                s[1] = c1
                s[2] = c2
                s[3] = c3
                s[4] = c4
                s[5] = c5
                s[6] = c6
                s[7] = c7
            }
            NB_1024 -> {
                var c00 = s[0]
                var c01 = s[1]
                var c02 = s[2]
                var c03 = s[3]
                var c04 = s[4]
                var c05 = s[5]
                var c06 = s[6]
                var c07 = s[7]
                var c08 = s[8]
                var c09 = s[9]
                var c10 = s[10]
                var c11 = s[11]
                var c12 = s[12]
                var c13 = s[13]
                var c14 = s[14]
                var c15 = s[15]
                var d: Long

                // NOTE: Row 7 is shifted by 11
                d = c00 xor c08 and -0x100000000000000L
                c00 = c00 xor d
                c08 = c08 xor d
                d = c01 xor c09 and -0x100000000000000L
                c01 = c01 xor d
                c09 = c09 xor d
                d = c02 xor c10 and -0x1000000000000L
                c02 = c02 xor d
                c10 = c10 xor d
                d = c03 xor c11 and -0x10000000000L
                c03 = c03 xor d
                c11 = c11 xor d
                d = c04 xor c12 and -0x100000000L
                c04 = c04 xor d
                c12 = c12 xor d
                d = c05 xor c13 and 0x00FFFFFFFF000000L
                c05 = c05 xor d
                c13 = c13 xor d
                d = c06 xor c14 and 0x00FFFFFFFFFF0000L
                c06 = c06 xor d
                c14 = c14 xor d
                d = c07 xor c15 and 0x00FFFFFFFFFFFF00L
                c07 = c07 xor d
                c15 = c15 xor d
                d = c00 xor c04 and 0x00FFFFFF00000000L
                c00 = c00 xor d
                c04 = c04 xor d
                d = c01 xor c05 and -0x1000000L
                c01 = c01 xor d
                c05 = c05 xor d
                d = c02 xor c06 and -0xff000000010000L
                c02 = c02 xor d
                c06 = c06 xor d
                d = c03 xor c07 and -0xffff0000000100L
                c03 = c03 xor d
                c07 = c07 xor d
                d = c08 xor c12 and 0x00FFFFFF00000000L
                c08 = c08 xor d
                c12 = c12 xor d
                d = c09 xor c13 and -0x1000000L
                c09 = c09 xor d
                c13 = c13 xor d
                d = c10 xor c14 and -0xff000000010000L
                c10 = c10 xor d
                c14 = c14 xor d
                d = c11 xor c15 and -0xffff0000000100L
                c11 = c11 xor d
                c15 = c15 xor d
                d = c00 xor c02 and -0xffff00010000L
                c00 = c00 xor d
                c02 = c02 xor d
                d = c01 xor c03 and 0x00FFFF0000FFFF00L
                c01 = c01 xor d
                c03 = c03 xor d
                d = c04 xor c06 and -0xffff00010000L
                c04 = c04 xor d
                c06 = c06 xor d
                d = c05 xor c07 and 0x00FFFF0000FFFF00L
                c05 = c05 xor d
                c07 = c07 xor d
                d = c08 xor c10 and -0xffff00010000L
                c08 = c08 xor d
                c10 = c10 xor d
                d = c09 xor c11 and 0x00FFFF0000FFFF00L
                c09 = c09 xor d
                c11 = c11 xor d
                d = c12 xor c14 and -0xffff00010000L
                c12 = c12 xor d
                c14 = c14 xor d
                d = c13 xor c15 and 0x00FFFF0000FFFF00L
                c13 = c13 xor d
                c15 = c15 xor d
                d = c00 xor c01 and -0xff00ff00ff0100L
                c00 = c00 xor d
                c01 = c01 xor d
                d = c02 xor c03 and -0xff00ff00ff0100L
                c02 = c02 xor d
                c03 = c03 xor d
                d = c04 xor c05 and -0xff00ff00ff0100L
                c04 = c04 xor d
                c05 = c05 xor d
                d = c06 xor c07 and -0xff00ff00ff0100L
                c06 = c06 xor d
                c07 = c07 xor d
                d = c08 xor c09 and -0xff00ff00ff0100L
                c08 = c08 xor d
                c09 = c09 xor d
                d = c10 xor c11 and -0xff00ff00ff0100L
                c10 = c10 xor d
                c11 = c11 xor d
                d = c12 xor c13 and -0xff00ff00ff0100L
                c12 = c12 xor d
                c13 = c13 xor d
                d = c14 xor c15 and -0xff00ff00ff0100L
                c14 = c14 xor d
                c15 = c15 xor d
                s[0] = c00
                s[1] = c01
                s[2] = c02
                s[3] = c03
                s[4] = c04
                s[5] = c05
                s[6] = c06
                s[7] = c07
                s[8] = c08
                s[9] = c09
                s[10] = c10
                s[11] = c11
                s[12] = c12
                s[13] = c13
                s[14] = c14
                s[15] = c15
            }
            else -> {
                throw IllegalStateException("unsupported state size: only 512/1024 are allowed")
            }
        }
    }

    private fun subBytes(s: LongArray) {
        for (i in 0 until columns) {
            val u = s[i]
            var lo = u.toInt()
            var hi = (u ushr 32).toInt()
            val t0 = S0[lo and 0xFF]
            val t1 = S1[lo ushr 8 and 0xFF]
            val t2 = S2[lo ushr 16 and 0xFF]
            val t3 = S3[lo ushr 24]
            lo = t0.toInt() and 0xFF or (t1.toInt() and 0xFF shl 8) or (t2.toInt() and 0xFF shl 16) or (t3.toInt() shl 24)
            val t4 = S0[hi and 0xFF]
            val t5 = S1[hi ushr 8 and 0xFF]
            val t6 = S2[hi ushr 16 and 0xFF]
            val t7 = S3[hi ushr 24]
            hi = t4.toInt() and 0xFF or (t5.toInt() and 0xFF shl 8) or (t6.toInt() and 0xFF shl 16) or (t7.toInt() shl 24)
            s[i] = (lo.toLong() and 0xFFFFFFFFL or (hi.toLong() shl 32))
        }
    }

    override fun copy(): DSTU7564 {
        return DSTU7564(this)
    }

    fun reset(other: DSTU7564) {
        copyIn(other)
    }

    companion object {

        /* Number of 8-byte words in operating state for <= 256-bit hash codes */
        private const val NB_512 = 8

        /* Number of 8-byte words in operating state for <= 512-bit hash codes */
        private const val NB_1024 = 16

        /* Number of rounds for 512-bit state */
        private const val NR_512 = 10

        /* Number of rounds for 1024-bit state */
        private const val NR_1024 = 14

        @Suppress("JoinDeclarationAndAssignment")
        private fun mixColumn(c: Long): Long {
//        // Calculate column multiplied by powers of 'x'
//        long x0 = c;
//        long x1 = ((x0 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x0 & 0x8080808080808080L) >>> 7) * 0x1DL);
//        long x2 = ((x1 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x1 & 0x8080808080808080L) >>> 7) * 0x1DL);
//        long x3 = ((x2 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x2 & 0x8080808080808080L) >>> 7) * 0x1DL);
//
//        // Calculate products with circulant matrix from (0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04)
//        long m0 = x0;
//        long m1 = x0;
//        long m2 = x0 ^ x2;
//        long m3 = x0;
//        long m4 = x3;
//        long m5 = x1 ^ x2;
//        long m6 = x0 ^ x1 ^ x2;
//        long m7 = x2;
//
//        // Assemble the rotated products
//        return m0
//            ^ circularRightLong(m1, 8)
//            ^ circularRightLong(m2, 16)
//            ^ circularRightLong(m3, 24)
//            ^ circularRightLong(m4, 32)
//            ^ circularRightLong(m5, 40)
//            ^ circularRightLong(m6, 48)
//            ^ circularRightLong(m7, 56);

            // Multiply elements by 'x'
            val x1 = c and 0x7F7F7F7F7F7F7F7FL shl 1 xor (c and -0x7f7f7f7f7f7f7f80L ushr 7) * 0x1DL
            var u: Long
            var v: Long
            u = circularRightLong(c, 8) xor c
            u = u xor circularRightLong(u, 16)
            u = u xor circularRightLong(c, 48)
            v = u xor c xor x1

            // Multiply elements by 'x^2'
            v = v and 0x3F3F3F3F3F3F3F3FL shl 2 xor (v and -0x7f7f7f7f7f7f7f80L ushr 6) * 0x1DL xor (v and 0x4040404040404040L ushr 6) * 0x1DL
            return u xor circularRightLong(v, 32) xor circularRightLong(x1, 40) xor circularRightLong(x1, 48)
        }

        private val S0 = byteArrayOf(
            0xa8.toByte(),
            0x43.toByte(),
            0x5f.toByte(),
            0x06.toByte(),
            0x6b.toByte(),
            0x75.toByte(),
            0x6c.toByte(),
            0x59.toByte(),
            0x71.toByte(),
            0xdf.toByte(),
            0x87.toByte(),
            0x95.toByte(),
            0x17.toByte(),
            0xf0.toByte(),
            0xd8.toByte(),
            0x09.toByte(),
            0x6d.toByte(),
            0xf3.toByte(),
            0x1d.toByte(),
            0xcb.toByte(),
            0xc9.toByte(),
            0x4d.toByte(),
            0x2c.toByte(),
            0xaf.toByte(),
            0x79.toByte(),
            0xe0.toByte(),
            0x97.toByte(),
            0xfd.toByte(),
            0x6f.toByte(),
            0x4b.toByte(),
            0x45.toByte(),
            0x39.toByte(),
            0x3e.toByte(),
            0xdd.toByte(),
            0xa3.toByte(),
            0x4f.toByte(),
            0xb4.toByte(),
            0xb6.toByte(),
            0x9a.toByte(),
            0x0e.toByte(),
            0x1f.toByte(),
            0xbf.toByte(),
            0x15.toByte(),
            0xe1.toByte(),
            0x49.toByte(),
            0xd2.toByte(),
            0x93.toByte(),
            0xc6.toByte(),
            0x92.toByte(),
            0x72.toByte(),
            0x9e.toByte(),
            0x61.toByte(),
            0xd1.toByte(),
            0x63.toByte(),
            0xfa.toByte(),
            0xee.toByte(),
            0xf4.toByte(),
            0x19.toByte(),
            0xd5.toByte(),
            0xad.toByte(),
            0x58.toByte(),
            0xa4.toByte(),
            0xbb.toByte(),
            0xa1.toByte(),
            0xdc.toByte(),
            0xf2.toByte(),
            0x83.toByte(),
            0x37.toByte(),
            0x42.toByte(),
            0xe4.toByte(),
            0x7a.toByte(),
            0x32.toByte(),
            0x9c.toByte(),
            0xcc.toByte(),
            0xab.toByte(),
            0x4a.toByte(),
            0x8f.toByte(),
            0x6e.toByte(),
            0x04.toByte(),
            0x27.toByte(),
            0x2e.toByte(),
            0xe7.toByte(),
            0xe2.toByte(),
            0x5a.toByte(),
            0x96.toByte(),
            0x16.toByte(),
            0x23.toByte(),
            0x2b.toByte(),
            0xc2.toByte(),
            0x65.toByte(),
            0x66.toByte(),
            0x0f.toByte(),
            0xbc.toByte(),
            0xa9.toByte(),
            0x47.toByte(),
            0x41.toByte(),
            0x34.toByte(),
            0x48.toByte(),
            0xfc.toByte(),
            0xb7.toByte(),
            0x6a.toByte(),
            0x88.toByte(),
            0xa5.toByte(),
            0x53.toByte(),
            0x86.toByte(),
            0xf9.toByte(),
            0x5b.toByte(),
            0xdb.toByte(),
            0x38.toByte(),
            0x7b.toByte(),
            0xc3.toByte(),
            0x1e.toByte(),
            0x22.toByte(),
            0x33.toByte(),
            0x24.toByte(),
            0x28.toByte(),
            0x36.toByte(),
            0xc7.toByte(),
            0xb2.toByte(),
            0x3b.toByte(),
            0x8e.toByte(),
            0x77.toByte(),
            0xba.toByte(),
            0xf5.toByte(),
            0x14.toByte(),
            0x9f.toByte(),
            0x08.toByte(),
            0x55.toByte(),
            0x9b.toByte(),
            0x4c.toByte(),
            0xfe.toByte(),
            0x60.toByte(),
            0x5c.toByte(),
            0xda.toByte(),
            0x18.toByte(),
            0x46.toByte(),
            0xcd.toByte(),
            0x7d.toByte(),
            0x21.toByte(),
            0xb0.toByte(),
            0x3f.toByte(),
            0x1b.toByte(),
            0x89.toByte(),
            0xff.toByte(),
            0xeb.toByte(),
            0x84.toByte(),
            0x69.toByte(),
            0x3a.toByte(),
            0x9d.toByte(),
            0xd7.toByte(),
            0xd3.toByte(),
            0x70.toByte(),
            0x67.toByte(),
            0x40.toByte(),
            0xb5.toByte(),
            0xde.toByte(),
            0x5d.toByte(),
            0x30.toByte(),
            0x91.toByte(),
            0xb1.toByte(),
            0x78.toByte(),
            0x11.toByte(),
            0x01.toByte(),
            0xe5.toByte(),
            0x00.toByte(),
            0x68.toByte(),
            0x98.toByte(),
            0xa0.toByte(),
            0xc5.toByte(),
            0x02.toByte(),
            0xa6.toByte(),
            0x74.toByte(),
            0x2d.toByte(),
            0x0b.toByte(),
            0xa2.toByte(),
            0x76.toByte(),
            0xb3.toByte(),
            0xbe.toByte(),
            0xce.toByte(),
            0xbd.toByte(),
            0xae.toByte(),
            0xe9.toByte(),
            0x8a.toByte(),
            0x31.toByte(),
            0x1c.toByte(),
            0xec.toByte(),
            0xf1.toByte(),
            0x99.toByte(),
            0x94.toByte(),
            0xaa.toByte(),
            0xf6.toByte(),
            0x26.toByte(),
            0x2f.toByte(),
            0xef.toByte(),
            0xe8.toByte(),
            0x8c.toByte(),
            0x35.toByte(),
            0x03.toByte(),
            0xd4.toByte(),
            0x7f.toByte(),
            0xfb.toByte(),
            0x05.toByte(),
            0xc1.toByte(),
            0x5e.toByte(),
            0x90.toByte(),
            0x20.toByte(),
            0x3d.toByte(),
            0x82.toByte(),
            0xf7.toByte(),
            0xea.toByte(),
            0x0a.toByte(),
            0x0d.toByte(),
            0x7e.toByte(),
            0xf8.toByte(),
            0x50.toByte(),
            0x1a.toByte(),
            0xc4.toByte(),
            0x07.toByte(),
            0x57.toByte(),
            0xb8.toByte(),
            0x3c.toByte(),
            0x62.toByte(),
            0xe3.toByte(),
            0xc8.toByte(),
            0xac.toByte(),
            0x52.toByte(),
            0x64.toByte(),
            0x10.toByte(),
            0xd0.toByte(),
            0xd9.toByte(),
            0x13.toByte(),
            0x0c.toByte(),
            0x12.toByte(),
            0x29.toByte(),
            0x51.toByte(),
            0xb9.toByte(),
            0xcf.toByte(),
            0xd6.toByte(),
            0x73.toByte(),
            0x8d.toByte(),
            0x81.toByte(),
            0x54.toByte(),
            0xc0.toByte(),
            0xed.toByte(),
            0x4e.toByte(),
            0x44.toByte(),
            0xa7.toByte(),
            0x2a.toByte(),
            0x85.toByte(),
            0x25.toByte(),
            0xe6.toByte(),
            0xca.toByte(),
            0x7c.toByte(),
            0x8b.toByte(),
            0x56.toByte(),
            0x80.toByte()
        )
        private val S1 = byteArrayOf(
            0xce.toByte(),
            0xbb.toByte(),
            0xeb.toByte(),
            0x92.toByte(),
            0xea.toByte(),
            0xcb.toByte(),
            0x13.toByte(),
            0xc1.toByte(),
            0xe9.toByte(),
            0x3a.toByte(),
            0xd6.toByte(),
            0xb2.toByte(),
            0xd2.toByte(),
            0x90.toByte(),
            0x17.toByte(),
            0xf8.toByte(),
            0x42.toByte(),
            0x15.toByte(),
            0x56.toByte(),
            0xb4.toByte(),
            0x65.toByte(),
            0x1c.toByte(),
            0x88.toByte(),
            0x43.toByte(),
            0xc5.toByte(),
            0x5c.toByte(),
            0x36.toByte(),
            0xba.toByte(),
            0xf5.toByte(),
            0x57.toByte(),
            0x67.toByte(),
            0x8d.toByte(),
            0x31.toByte(),
            0xf6.toByte(),
            0x64.toByte(),
            0x58.toByte(),
            0x9e.toByte(),
            0xf4.toByte(),
            0x22.toByte(),
            0xaa.toByte(),
            0x75.toByte(),
            0x0f.toByte(),
            0x02.toByte(),
            0xb1.toByte(),
            0xdf.toByte(),
            0x6d.toByte(),
            0x73.toByte(),
            0x4d.toByte(),
            0x7c.toByte(),
            0x26.toByte(),
            0x2e.toByte(),
            0xf7.toByte(),
            0x08.toByte(),
            0x5d.toByte(),
            0x44.toByte(),
            0x3e.toByte(),
            0x9f.toByte(),
            0x14.toByte(),
            0xc8.toByte(),
            0xae.toByte(),
            0x54.toByte(),
            0x10.toByte(),
            0xd8.toByte(),
            0xbc.toByte(),
            0x1a.toByte(),
            0x6b.toByte(),
            0x69.toByte(),
            0xf3.toByte(),
            0xbd.toByte(),
            0x33.toByte(),
            0xab.toByte(),
            0xfa.toByte(),
            0xd1.toByte(),
            0x9b.toByte(),
            0x68.toByte(),
            0x4e.toByte(),
            0x16.toByte(),
            0x95.toByte(),
            0x91.toByte(),
            0xee.toByte(),
            0x4c.toByte(),
            0x63.toByte(),
            0x8e.toByte(),
            0x5b.toByte(),
            0xcc.toByte(),
            0x3c.toByte(),
            0x19.toByte(),
            0xa1.toByte(),
            0x81.toByte(),
            0x49.toByte(),
            0x7b.toByte(),
            0xd9.toByte(),
            0x6f.toByte(),
            0x37.toByte(),
            0x60.toByte(),
            0xca.toByte(),
            0xe7.toByte(),
            0x2b.toByte(),
            0x48.toByte(),
            0xfd.toByte(),
            0x96.toByte(),
            0x45.toByte(),
            0xfc.toByte(),
            0x41.toByte(),
            0x12.toByte(),
            0x0d.toByte(),
            0x79.toByte(),
            0xe5.toByte(),
            0x89.toByte(),
            0x8c.toByte(),
            0xe3.toByte(),
            0x20.toByte(),
            0x30.toByte(),
            0xdc.toByte(),
            0xb7.toByte(),
            0x6c.toByte(),
            0x4a.toByte(),
            0xb5.toByte(),
            0x3f.toByte(),
            0x97.toByte(),
            0xd4.toByte(),
            0x62.toByte(),
            0x2d.toByte(),
            0x06.toByte(),
            0xa4.toByte(),
            0xa5.toByte(),
            0x83.toByte(),
            0x5f.toByte(),
            0x2a.toByte(),
            0xda.toByte(),
            0xc9.toByte(),
            0x00.toByte(),
            0x7e.toByte(),
            0xa2.toByte(),
            0x55.toByte(),
            0xbf.toByte(),
            0x11.toByte(),
            0xd5.toByte(),
            0x9c.toByte(),
            0xcf.toByte(),
            0x0e.toByte(),
            0x0a.toByte(),
            0x3d.toByte(),
            0x51.toByte(),
            0x7d.toByte(),
            0x93.toByte(),
            0x1b.toByte(),
            0xfe.toByte(),
            0xc4.toByte(),
            0x47.toByte(),
            0x09.toByte(),
            0x86.toByte(),
            0x0b.toByte(),
            0x8f.toByte(),
            0x9d.toByte(),
            0x6a.toByte(),
            0x07.toByte(),
            0xb9.toByte(),
            0xb0.toByte(),
            0x98.toByte(),
            0x18.toByte(),
            0x32.toByte(),
            0x71.toByte(),
            0x4b.toByte(),
            0xef.toByte(),
            0x3b.toByte(),
            0x70.toByte(),
            0xa0.toByte(),
            0xe4.toByte(),
            0x40.toByte(),
            0xff.toByte(),
            0xc3.toByte(),
            0xa9.toByte(),
            0xe6.toByte(),
            0x78.toByte(),
            0xf9.toByte(),
            0x8b.toByte(),
            0x46.toByte(),
            0x80.toByte(),
            0x1e.toByte(),
            0x38.toByte(),
            0xe1.toByte(),
            0xb8.toByte(),
            0xa8.toByte(),
            0xe0.toByte(),
            0x0c.toByte(),
            0x23.toByte(),
            0x76.toByte(),
            0x1d.toByte(),
            0x25.toByte(),
            0x24.toByte(),
            0x05.toByte(),
            0xf1.toByte(),
            0x6e.toByte(),
            0x94.toByte(),
            0x28.toByte(),
            0x9a.toByte(),
            0x84.toByte(),
            0xe8.toByte(),
            0xa3.toByte(),
            0x4f.toByte(),
            0x77.toByte(),
            0xd3.toByte(),
            0x85.toByte(),
            0xe2.toByte(),
            0x52.toByte(),
            0xf2.toByte(),
            0x82.toByte(),
            0x50.toByte(),
            0x7a.toByte(),
            0x2f.toByte(),
            0x74.toByte(),
            0x53.toByte(),
            0xb3.toByte(),
            0x61.toByte(),
            0xaf.toByte(),
            0x39.toByte(),
            0x35.toByte(),
            0xde.toByte(),
            0xcd.toByte(),
            0x1f.toByte(),
            0x99.toByte(),
            0xac.toByte(),
            0xad.toByte(),
            0x72.toByte(),
            0x2c.toByte(),
            0xdd.toByte(),
            0xd0.toByte(),
            0x87.toByte(),
            0xbe.toByte(),
            0x5e.toByte(),
            0xa6.toByte(),
            0xec.toByte(),
            0x04.toByte(),
            0xc6.toByte(),
            0x03.toByte(),
            0x34.toByte(),
            0xfb.toByte(),
            0xdb.toByte(),
            0x59.toByte(),
            0xb6.toByte(),
            0xc2.toByte(),
            0x01.toByte(),
            0xf0.toByte(),
            0x5a.toByte(),
            0xed.toByte(),
            0xa7.toByte(),
            0x66.toByte(),
            0x21.toByte(),
            0x7f.toByte(),
            0x8a.toByte(),
            0x27.toByte(),
            0xc7.toByte(),
            0xc0.toByte(),
            0x29.toByte(),
            0xd7.toByte()
        )
        private val S2 = byteArrayOf(
            0x93.toByte(),
            0xd9.toByte(),
            0x9a.toByte(),
            0xb5.toByte(),
            0x98.toByte(),
            0x22.toByte(),
            0x45.toByte(),
            0xfc.toByte(),
            0xba.toByte(),
            0x6a.toByte(),
            0xdf.toByte(),
            0x02.toByte(),
            0x9f.toByte(),
            0xdc.toByte(),
            0x51.toByte(),
            0x59.toByte(),
            0x4a.toByte(),
            0x17.toByte(),
            0x2b.toByte(),
            0xc2.toByte(),
            0x94.toByte(),
            0xf4.toByte(),
            0xbb.toByte(),
            0xa3.toByte(),
            0x62.toByte(),
            0xe4.toByte(),
            0x71.toByte(),
            0xd4.toByte(),
            0xcd.toByte(),
            0x70.toByte(),
            0x16.toByte(),
            0xe1.toByte(),
            0x49.toByte(),
            0x3c.toByte(),
            0xc0.toByte(),
            0xd8.toByte(),
            0x5c.toByte(),
            0x9b.toByte(),
            0xad.toByte(),
            0x85.toByte(),
            0x53.toByte(),
            0xa1.toByte(),
            0x7a.toByte(),
            0xc8.toByte(),
            0x2d.toByte(),
            0xe0.toByte(),
            0xd1.toByte(),
            0x72.toByte(),
            0xa6.toByte(),
            0x2c.toByte(),
            0xc4.toByte(),
            0xe3.toByte(),
            0x76.toByte(),
            0x78.toByte(),
            0xb7.toByte(),
            0xb4.toByte(),
            0x09.toByte(),
            0x3b.toByte(),
            0x0e.toByte(),
            0x41.toByte(),
            0x4c.toByte(),
            0xde.toByte(),
            0xb2.toByte(),
            0x90.toByte(),
            0x25.toByte(),
            0xa5.toByte(),
            0xd7.toByte(),
            0x03.toByte(),
            0x11.toByte(),
            0x00.toByte(),
            0xc3.toByte(),
            0x2e.toByte(),
            0x92.toByte(),
            0xef.toByte(),
            0x4e.toByte(),
            0x12.toByte(),
            0x9d.toByte(),
            0x7d.toByte(),
            0xcb.toByte(),
            0x35.toByte(),
            0x10.toByte(),
            0xd5.toByte(),
            0x4f.toByte(),
            0x9e.toByte(),
            0x4d.toByte(),
            0xa9.toByte(),
            0x55.toByte(),
            0xc6.toByte(),
            0xd0.toByte(),
            0x7b.toByte(),
            0x18.toByte(),
            0x97.toByte(),
            0xd3.toByte(),
            0x36.toByte(),
            0xe6.toByte(),
            0x48.toByte(),
            0x56.toByte(),
            0x81.toByte(),
            0x8f.toByte(),
            0x77.toByte(),
            0xcc.toByte(),
            0x9c.toByte(),
            0xb9.toByte(),
            0xe2.toByte(),
            0xac.toByte(),
            0xb8.toByte(),
            0x2f.toByte(),
            0x15.toByte(),
            0xa4.toByte(),
            0x7c.toByte(),
            0xda.toByte(),
            0x38.toByte(),
            0x1e.toByte(),
            0x0b.toByte(),
            0x05.toByte(),
            0xd6.toByte(),
            0x14.toByte(),
            0x6e.toByte(),
            0x6c.toByte(),
            0x7e.toByte(),
            0x66.toByte(),
            0xfd.toByte(),
            0xb1.toByte(),
            0xe5.toByte(),
            0x60.toByte(),
            0xaf.toByte(),
            0x5e.toByte(),
            0x33.toByte(),
            0x87.toByte(),
            0xc9.toByte(),
            0xf0.toByte(),
            0x5d.toByte(),
            0x6d.toByte(),
            0x3f.toByte(),
            0x88.toByte(),
            0x8d.toByte(),
            0xc7.toByte(),
            0xf7.toByte(),
            0x1d.toByte(),
            0xe9.toByte(),
            0xec.toByte(),
            0xed.toByte(),
            0x80.toByte(),
            0x29.toByte(),
            0x27.toByte(),
            0xcf.toByte(),
            0x99.toByte(),
            0xa8.toByte(),
            0x50.toByte(),
            0x0f.toByte(),
            0x37.toByte(),
            0x24.toByte(),
            0x28.toByte(),
            0x30.toByte(),
            0x95.toByte(),
            0xd2.toByte(),
            0x3e.toByte(),
            0x5b.toByte(),
            0x40.toByte(),
            0x83.toByte(),
            0xb3.toByte(),
            0x69.toByte(),
            0x57.toByte(),
            0x1f.toByte(),
            0x07.toByte(),
            0x1c.toByte(),
            0x8a.toByte(),
            0xbc.toByte(),
            0x20.toByte(),
            0xeb.toByte(),
            0xce.toByte(),
            0x8e.toByte(),
            0xab.toByte(),
            0xee.toByte(),
            0x31.toByte(),
            0xa2.toByte(),
            0x73.toByte(),
            0xf9.toByte(),
            0xca.toByte(),
            0x3a.toByte(),
            0x1a.toByte(),
            0xfb.toByte(),
            0x0d.toByte(),
            0xc1.toByte(),
            0xfe.toByte(),
            0xfa.toByte(),
            0xf2.toByte(),
            0x6f.toByte(),
            0xbd.toByte(),
            0x96.toByte(),
            0xdd.toByte(),
            0x43.toByte(),
            0x52.toByte(),
            0xb6.toByte(),
            0x08.toByte(),
            0xf3.toByte(),
            0xae.toByte(),
            0xbe.toByte(),
            0x19.toByte(),
            0x89.toByte(),
            0x32.toByte(),
            0x26.toByte(),
            0xb0.toByte(),
            0xea.toByte(),
            0x4b.toByte(),
            0x64.toByte(),
            0x84.toByte(),
            0x82.toByte(),
            0x6b.toByte(),
            0xf5.toByte(),
            0x79.toByte(),
            0xbf.toByte(),
            0x01.toByte(),
            0x5f.toByte(),
            0x75.toByte(),
            0x63.toByte(),
            0x1b.toByte(),
            0x23.toByte(),
            0x3d.toByte(),
            0x68.toByte(),
            0x2a.toByte(),
            0x65.toByte(),
            0xe8.toByte(),
            0x91.toByte(),
            0xf6.toByte(),
            0xff.toByte(),
            0x13.toByte(),
            0x58.toByte(),
            0xf1.toByte(),
            0x47.toByte(),
            0x0a.toByte(),
            0x7f.toByte(),
            0xc5.toByte(),
            0xa7.toByte(),
            0xe7.toByte(),
            0x61.toByte(),
            0x5a.toByte(),
            0x06.toByte(),
            0x46.toByte(),
            0x44.toByte(),
            0x42.toByte(),
            0x04.toByte(),
            0xa0.toByte(),
            0xdb.toByte(),
            0x39.toByte(),
            0x86.toByte(),
            0x54.toByte(),
            0xaa.toByte(),
            0x8c.toByte(),
            0x34.toByte(),
            0x21.toByte(),
            0x8b.toByte(),
            0xf8.toByte(),
            0x0c.toByte(),
            0x74.toByte(),
            0x67.toByte()
        )
        private val S3 = byteArrayOf(
            0x68.toByte(),
            0x8d.toByte(),
            0xca.toByte(),
            0x4d.toByte(),
            0x73.toByte(),
            0x4b.toByte(),
            0x4e.toByte(),
            0x2a.toByte(),
            0xd4.toByte(),
            0x52.toByte(),
            0x26.toByte(),
            0xb3.toByte(),
            0x54.toByte(),
            0x1e.toByte(),
            0x19.toByte(),
            0x1f.toByte(),
            0x22.toByte(),
            0x03.toByte(),
            0x46.toByte(),
            0x3d.toByte(),
            0x2d.toByte(),
            0x4a.toByte(),
            0x53.toByte(),
            0x83.toByte(),
            0x13.toByte(),
            0x8a.toByte(),
            0xb7.toByte(),
            0xd5.toByte(),
            0x25.toByte(),
            0x79.toByte(),
            0xf5.toByte(),
            0xbd.toByte(),
            0x58.toByte(),
            0x2f.toByte(),
            0x0d.toByte(),
            0x02.toByte(),
            0xed.toByte(),
            0x51.toByte(),
            0x9e.toByte(),
            0x11.toByte(),
            0xf2.toByte(),
            0x3e.toByte(),
            0x55.toByte(),
            0x5e.toByte(),
            0xd1.toByte(),
            0x16.toByte(),
            0x3c.toByte(),
            0x66.toByte(),
            0x70.toByte(),
            0x5d.toByte(),
            0xf3.toByte(),
            0x45.toByte(),
            0x40.toByte(),
            0xcc.toByte(),
            0xe8.toByte(),
            0x94.toByte(),
            0x56.toByte(),
            0x08.toByte(),
            0xce.toByte(),
            0x1a.toByte(),
            0x3a.toByte(),
            0xd2.toByte(),
            0xe1.toByte(),
            0xdf.toByte(),
            0xb5.toByte(),
            0x38.toByte(),
            0x6e.toByte(),
            0x0e.toByte(),
            0xe5.toByte(),
            0xf4.toByte(),
            0xf9.toByte(),
            0x86.toByte(),
            0xe9.toByte(),
            0x4f.toByte(),
            0xd6.toByte(),
            0x85.toByte(),
            0x23.toByte(),
            0xcf.toByte(),
            0x32.toByte(),
            0x99.toByte(),
            0x31.toByte(),
            0x14.toByte(),
            0xae.toByte(),
            0xee.toByte(),
            0xc8.toByte(),
            0x48.toByte(),
            0xd3.toByte(),
            0x30.toByte(),
            0xa1.toByte(),
            0x92.toByte(),
            0x41.toByte(),
            0xb1.toByte(),
            0x18.toByte(),
            0xc4.toByte(),
            0x2c.toByte(),
            0x71.toByte(),
            0x72.toByte(),
            0x44.toByte(),
            0x15.toByte(),
            0xfd.toByte(),
            0x37.toByte(),
            0xbe.toByte(),
            0x5f.toByte(),
            0xaa.toByte(),
            0x9b.toByte(),
            0x88.toByte(),
            0xd8.toByte(),
            0xab.toByte(),
            0x89.toByte(),
            0x9c.toByte(),
            0xfa.toByte(),
            0x60.toByte(),
            0xea.toByte(),
            0xbc.toByte(),
            0x62.toByte(),
            0x0c.toByte(),
            0x24.toByte(),
            0xa6.toByte(),
            0xa8.toByte(),
            0xec.toByte(),
            0x67.toByte(),
            0x20.toByte(),
            0xdb.toByte(),
            0x7c.toByte(),
            0x28.toByte(),
            0xdd.toByte(),
            0xac.toByte(),
            0x5b.toByte(),
            0x34.toByte(),
            0x7e.toByte(),
            0x10.toByte(),
            0xf1.toByte(),
            0x7b.toByte(),
            0x8f.toByte(),
            0x63.toByte(),
            0xa0.toByte(),
            0x05.toByte(),
            0x9a.toByte(),
            0x43.toByte(),
            0x77.toByte(),
            0x21.toByte(),
            0xbf.toByte(),
            0x27.toByte(),
            0x09.toByte(),
            0xc3.toByte(),
            0x9f.toByte(),
            0xb6.toByte(),
            0xd7.toByte(),
            0x29.toByte(),
            0xc2.toByte(),
            0xeb.toByte(),
            0xc0.toByte(),
            0xa4.toByte(),
            0x8b.toByte(),
            0x8c.toByte(),
            0x1d.toByte(),
            0xfb.toByte(),
            0xff.toByte(),
            0xc1.toByte(),
            0xb2.toByte(),
            0x97.toByte(),
            0x2e.toByte(),
            0xf8.toByte(),
            0x65.toByte(),
            0xf6.toByte(),
            0x75.toByte(),
            0x07.toByte(),
            0x04.toByte(),
            0x49.toByte(),
            0x33.toByte(),
            0xe4.toByte(),
            0xd9.toByte(),
            0xb9.toByte(),
            0xd0.toByte(),
            0x42.toByte(),
            0xc7.toByte(),
            0x6c.toByte(),
            0x90.toByte(),
            0x00.toByte(),
            0x8e.toByte(),
            0x6f.toByte(),
            0x50.toByte(),
            0x01.toByte(),
            0xc5.toByte(),
            0xda.toByte(),
            0x47.toByte(),
            0x3f.toByte(),
            0xcd.toByte(),
            0x69.toByte(),
            0xa2.toByte(),
            0xe2.toByte(),
            0x7a.toByte(),
            0xa7.toByte(),
            0xc6.toByte(),
            0x93.toByte(),
            0x0f.toByte(),
            0x0a.toByte(),
            0x06.toByte(),
            0xe6.toByte(),
            0x2b.toByte(),
            0x96.toByte(),
            0xa3.toByte(),
            0x1c.toByte(),
            0xaf.toByte(),
            0x6a.toByte(),
            0x12.toByte(),
            0x84.toByte(),
            0x39.toByte(),
            0xe7.toByte(),
            0xb0.toByte(),
            0x82.toByte(),
            0xf7.toByte(),
            0xfe.toByte(),
            0x9d.toByte(),
            0x87.toByte(),
            0x5c.toByte(),
            0x81.toByte(),
            0x35.toByte(),
            0xde.toByte(),
            0xb4.toByte(),
            0xa5.toByte(),
            0xfc.toByte(),
            0x80.toByte(),
            0xef.toByte(),
            0xcb.toByte(),
            0xbb.toByte(),
            0x6b.toByte(),
            0x76.toByte(),
            0xba.toByte(),
            0x5a.toByte(),
            0x7d.toByte(),
            0x78.toByte(),
            0x0b.toByte(),
            0x95.toByte(),
            0xe3.toByte(),
            0xad.toByte(),
            0x74.toByte(),
            0x98.toByte(),
            0x3b.toByte(),
            0x36.toByte(),
            0x64.toByte(),
            0x6d.toByte(),
            0xdc.toByte(),
            0xf0.toByte(),
            0x59.toByte(),
            0xa9.toByte(),
            0x4c.toByte(),
            0x17.toByte(),
            0x7f.toByte(),
            0x91.toByte(),
            0xb8.toByte(),
            0xc9.toByte(),
            0x57.toByte(),
            0x1b.toByte(),
            0xe0.toByte(),
            0x61.toByte()
        )
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        doFinal(digest, 0)
        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val blockLength: Int
        get() = byteLength

    override fun toString(): String {
        return "DSTU7564-${digestLength ushr 3}"
    }
}
