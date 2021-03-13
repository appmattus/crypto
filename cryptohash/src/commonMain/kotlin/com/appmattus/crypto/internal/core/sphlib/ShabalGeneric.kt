/*
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
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

package com.appmattus.crypto.internal.core.sphlib

import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.decodeLEInt

/**
 * This class implements Shabal for all output sizes from 32 to 512 bits
 * (inclusive, only multiples of 32 are supported). The output size must
 * be provided as parameter to the constructor. Alternatively, you may
 * use the [Shabal192], [Shabal224], [Shabal256],
 * [Shabal384] or [Shabal512] classes for size-specific
 * variants which offer a nullary constructor.
 *
 * @version $Revision: 231 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 *
 * Create the object. The output size must be a multiple of 32,
 * between 32 and 512 (inclusive).
 *
 * @param outSize   the intended output size
 */
@Suppress("TooManyFunctions", "MagicNumber")
internal class ShabalGeneric(private val outSize: Int) : Digest<ShabalGeneric> {

    private var outSizeW32 = outSize ushr 5
    private val buf: ByteArray = ByteArray(64)
    private var ptr = 0
    private val state: IntArray = IntArray(44)
    private var w: Long = 0

    init {
        if (outSize < 32 || outSize > 512 || outSize and 31 != 0) throw IllegalArgumentException(
            "invalid Shabal output size: $outSize"
        )
        reset()
    }

    override fun update(input: Byte) {
        buf[ptr++] = input
        if (ptr == 64) {
            w = core(state, w, buf, 0, 1)
            ptr = 0
        }
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    @Suppress("NAME_SHADOWING")
    override fun update(input: ByteArray, offset: Int, length: Int) {
        var off = offset
        var len = length
        if (ptr != 0) {
            val rlen = 64 - ptr
            if (len < rlen) {
                input.copyInto(buf, ptr, off, off + len)
                ptr += len
                return
            } else {
                input.copyInto(buf, ptr, off, off + rlen)
                off += rlen
                len -= rlen
                w = core(state, w, buf, 0, 1)
            }
        }
        val num = len ushr 6
        if (num > 0) {
            w = core(state, w, input, off, num)
            off += num shl 6
            len = len and 63
        }
        input.copyInto(buf, 0, off, off + len)
        ptr = len
    }

    override val digestLength: Int
        get() = outSizeW32 shl 2

    override fun digest(): ByteArray {
        val n = digestLength
        val out = ByteArray(n)
        digest(out, 0, n)
        return out
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input, 0, input.size)
        return digest()
    }

    @Suppress("NAME_SHADOWING")
    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        var len = length
        val dlen = digestLength
        if (len > dlen) len = dlen
        buf[ptr++] = 0x80.toByte()
        for (i in ptr..63) buf[i] = 0
        for (i in 0..3) {
            w = core(state, w, buf, 0, 1)
            w--
        }
        var j = 44 - (dlen ushr 2)
        var w = 0
        for (i in 0 until len) {
            if (i and 3 == 0) w = state[j++]
            output[i] = w.toByte()
            w = w ushr 8
        }
        reset()
        return len
    }

    override fun reset() {
        getIV(outSizeW32).copyInto(state, 0, 0, 44)
        w = 1
        ptr = 0
    }

    override fun copy(): ShabalGeneric {
        val d = ShabalGeneric(outSize)
        d.outSizeW32 = outSizeW32
        buf.copyInto(d.buf, 0, 0, ptr)
        d.ptr = ptr
        state.copyInto(d.state, 0, 0, 44)
        d.w = w
        return d
    }

    override val blockLength: Int
        get() = 64

    override fun toString(): String {
        return "Shabal-" + (digestLength shl 3)
    }

    private fun getIV(outSizeW32: Int): IntArray {
        // var iv = IVs[outSizeW32 - 1]
        // if (iv == null) {
        val outSize = outSizeW32 shl 5

        val state = IntArray(44)
        val buf = ByteArray(64)

        for (i in 0..43) state[i] = 0
        var w = -1L
        for (i in 0..15) {
            buf[(i shl 2) + 0] = (outSize + i).toByte()
            buf[(i shl 2) + 1] = (outSize + i ushr 8).toByte()
        }
        w = core(state, w, buf, 0, 1)
        for (i in 0..15) {
            buf[(i shl 2) + 0] = (outSize + i + 16).toByte()
            buf[(i shl 2) + 1] = (outSize + i + 16 ushr 8).toByte()
        }
        core(state, w, buf, 0, 1)
        return state
        // iv = IVs[outSizeW32 - 1]
        // }
        // return iv!!
    }

    companion object {
        /**
         * Returns new w
         */
        @Suppress("NAME_SHADOWING", "JoinDeclarationAndAssignment", "LongMethod")
        private fun core(state: IntArray, w: Long, data: ByteArray, off: Int, num: Int): Long {
            var w = w
            var off = off
            var num = num
            var a0 = state[0]
            var a1 = state[1]
            var a2 = state[2]
            var a3 = state[3]
            var a4 = state[4]
            var a5 = state[5]
            var a6 = state[6]
            var a7 = state[7]
            var a8 = state[8]
            var a9 = state[9]
            var aa = state[10]
            var ab = state[11]
            var b0 = state[12]
            var b1 = state[13]
            var b2 = state[14]
            var b3 = state[15]
            var b4 = state[16]
            var b5 = state[17]
            var b6 = state[18]
            var b7 = state[19]
            var b8 = state[20]
            var b9 = state[21]
            var ba = state[22]
            var bb = state[23]
            var bc = state[24]
            var bd = state[25]
            var be = state[26]
            var bf = state[27]
            var c0 = state[28]
            var c1 = state[29]
            var c2 = state[30]
            var c3 = state[31]
            var c4 = state[32]
            var c5 = state[33]
            var c6 = state[34]
            var c7 = state[35]
            var c8 = state[36]
            var c9 = state[37]
            var ca = state[38]
            var cb = state[39]
            var cc = state[40]
            var cd = state[41]
            var ce = state[42]
            var cf = state[43]
            while (num-- > 0) {
                val m0 = decodeLEInt(data, off + 0)
                b0 += m0
                b0 = b0 shl 17 or (b0 ushr 15)
                val m1 = decodeLEInt(data, off + 4)
                b1 += m1
                b1 = b1 shl 17 or (b1 ushr 15)
                val m2 = decodeLEInt(data, off + 8)
                b2 += m2
                b2 = b2 shl 17 or (b2 ushr 15)
                val m3 = decodeLEInt(data, off + 12)
                b3 += m3
                b3 = b3 shl 17 or (b3 ushr 15)
                val m4 = decodeLEInt(data, off + 16)
                b4 += m4
                b4 = b4 shl 17 or (b4 ushr 15)
                val m5 = decodeLEInt(data, off + 20)
                b5 += m5
                b5 = b5 shl 17 or (b5 ushr 15)
                val m6 = decodeLEInt(data, off + 24)
                b6 += m6
                b6 = b6 shl 17 or (b6 ushr 15)
                val m7 = decodeLEInt(data, off + 28)
                b7 += m7
                b7 = b7 shl 17 or (b7 ushr 15)
                val m8 = decodeLEInt(data, off + 32)
                b8 += m8
                b8 = b8 shl 17 or (b8 ushr 15)
                val m9 = decodeLEInt(data, off + 36)
                b9 += m9
                b9 = b9 shl 17 or (b9 ushr 15)
                val ma = decodeLEInt(data, off + 40)
                ba += ma
                ba = ba shl 17 or (ba ushr 15)
                val mb = decodeLEInt(data, off + 44)
                bb += mb
                bb = bb shl 17 or (bb ushr 15)
                val mc = decodeLEInt(data, off + 48)
                bc += mc
                bc = bc shl 17 or (bc ushr 15)
                val md = decodeLEInt(data, off + 52)
                bd += md
                bd = bd shl 17 or (bd ushr 15)
                val me = decodeLEInt(data, off + 56)
                be += me
                be = be shl 17 or (be ushr 15)
                val mf = decodeLEInt(data, off + 60)
                bf += mf
                bf = bf shl 17 or (bf ushr 15)
                off += 64
                a0 = a0 xor w.toInt()
                a1 = a1 xor (w ushr 32).toInt()
                w++
                a0 = ((a0 xor (ab shl 15 or (ab ushr 17)) * 5 xor c8) * 3
                        xor bd xor (b9 and b6.inv()) xor m0)
                b0 = (b0 shl 1 or (b0 ushr 31)).inv() xor a0
                a1 = ((a1 xor (a0 shl 15 or (a0 ushr 17)) * 5 xor c7) * 3
                        xor be xor (ba and b7.inv()) xor m1)
                b1 = (b1 shl 1 or (b1 ushr 31)).inv() xor a1
                a2 = ((a2 xor (a1 shl 15 or (a1 ushr 17)) * 5 xor c6) * 3
                        xor bf xor (bb and b8.inv()) xor m2)
                b2 = (b2 shl 1 or (b2 ushr 31)).inv() xor a2
                a3 = ((a3 xor (a2 shl 15 or (a2 ushr 17)) * 5 xor c5) * 3
                        xor b0 xor (bc and b9.inv()) xor m3)
                b3 = (b3 shl 1 or (b3 ushr 31)).inv() xor a3
                a4 = ((a4 xor (a3 shl 15 or (a3 ushr 17)) * 5 xor c4) * 3
                        xor b1 xor (bd and ba.inv()) xor m4)
                b4 = (b4 shl 1 or (b4 ushr 31)).inv() xor a4
                a5 = ((a5 xor (a4 shl 15 or (a4 ushr 17)) * 5 xor c3) * 3
                        xor b2 xor (be and bb.inv()) xor m5)
                b5 = (b5 shl 1 or (b5 ushr 31)).inv() xor a5
                a6 = ((a6 xor (a5 shl 15 or (a5 ushr 17)) * 5 xor c2) * 3
                        xor b3 xor (bf and bc.inv()) xor m6)
                b6 = (b6 shl 1 or (b6 ushr 31)).inv() xor a6
                a7 = ((a7 xor (a6 shl 15 or (a6 ushr 17)) * 5 xor c1) * 3
                        xor b4 xor (b0 and bd.inv()) xor m7)
                b7 = (b7 shl 1 or (b7 ushr 31)).inv() xor a7
                a8 = ((a8 xor (a7 shl 15 or (a7 ushr 17)) * 5 xor c0) * 3
                        xor b5 xor (b1 and be.inv()) xor m8)
                b8 = (b8 shl 1 or (b8 ushr 31)).inv() xor a8
                a9 = ((a9 xor (a8 shl 15 or (a8 ushr 17)) * 5 xor cf) * 3
                        xor b6 xor (b2 and bf.inv()) xor m9)
                b9 = (b9 shl 1 or (b9 ushr 31)).inv() xor a9
                aa = ((aa xor (a9 shl 15 or (a9 ushr 17)) * 5 xor ce) * 3
                        xor b7 xor (b3 and b0.inv()) xor ma)
                ba = (ba shl 1 or (ba ushr 31)).inv() xor aa
                ab = ((ab xor (aa shl 15 or (aa ushr 17)) * 5 xor cd) * 3
                        xor b8 xor (b4 and b1.inv()) xor mb)
                bb = (bb shl 1 or (bb ushr 31)).inv() xor ab
                a0 = ((a0 xor (ab shl 15 or (ab ushr 17)) * 5 xor cc) * 3
                        xor b9 xor (b5 and b2.inv()) xor mc)
                bc = (bc shl 1 or (bc ushr 31)).inv() xor a0
                a1 = ((a1 xor (a0 shl 15 or (a0 ushr 17)) * 5 xor cb) * 3
                        xor ba xor (b6 and b3.inv()) xor md)
                bd = (bd shl 1 or (bd ushr 31)).inv() xor a1
                a2 = ((a2 xor (a1 shl 15 or (a1 ushr 17)) * 5 xor ca) * 3
                        xor bb xor (b7 and b4.inv()) xor me)
                be = (be shl 1 or (be ushr 31)).inv() xor a2
                a3 = ((a3 xor (a2 shl 15 or (a2 ushr 17)) * 5 xor c9) * 3
                        xor bc xor (b8 and b5.inv()) xor mf)
                bf = (bf shl 1 or (bf ushr 31)).inv() xor a3
                a4 = ((a4 xor (a3 shl 15 or (a3 ushr 17)) * 5 xor c8) * 3
                        xor bd xor (b9 and b6.inv()) xor m0)
                b0 = (b0 shl 1 or (b0 ushr 31)).inv() xor a4
                a5 = ((a5 xor (a4 shl 15 or (a4 ushr 17)) * 5 xor c7) * 3
                        xor be xor (ba and b7.inv()) xor m1)
                b1 = (b1 shl 1 or (b1 ushr 31)).inv() xor a5
                a6 = ((a6 xor (a5 shl 15 or (a5 ushr 17)) * 5 xor c6) * 3
                        xor bf xor (bb and b8.inv()) xor m2)
                b2 = (b2 shl 1 or (b2 ushr 31)).inv() xor a6
                a7 = ((a7 xor (a6 shl 15 or (a6 ushr 17)) * 5 xor c5) * 3
                        xor b0 xor (bc and b9.inv()) xor m3)
                b3 = (b3 shl 1 or (b3 ushr 31)).inv() xor a7
                a8 = ((a8 xor (a7 shl 15 or (a7 ushr 17)) * 5 xor c4) * 3
                        xor b1 xor (bd and ba.inv()) xor m4)
                b4 = (b4 shl 1 or (b4 ushr 31)).inv() xor a8
                a9 = ((a9 xor (a8 shl 15 or (a8 ushr 17)) * 5 xor c3) * 3
                        xor b2 xor (be and bb.inv()) xor m5)
                b5 = (b5 shl 1 or (b5 ushr 31)).inv() xor a9
                aa = ((aa xor (a9 shl 15 or (a9 ushr 17)) * 5 xor c2) * 3
                        xor b3 xor (bf and bc.inv()) xor m6)
                b6 = (b6 shl 1 or (b6 ushr 31)).inv() xor aa
                ab = ((ab xor (aa shl 15 or (aa ushr 17)) * 5 xor c1) * 3
                        xor b4 xor (b0 and bd.inv()) xor m7)
                b7 = (b7 shl 1 or (b7 ushr 31)).inv() xor ab
                a0 = ((a0 xor (ab shl 15 or (ab ushr 17)) * 5 xor c0) * 3
                        xor b5 xor (b1 and be.inv()) xor m8)
                b8 = (b8 shl 1 or (b8 ushr 31)).inv() xor a0
                a1 = ((a1 xor (a0 shl 15 or (a0 ushr 17)) * 5 xor cf) * 3
                        xor b6 xor (b2 and bf.inv()) xor m9)
                b9 = (b9 shl 1 or (b9 ushr 31)).inv() xor a1
                a2 = ((a2 xor (a1 shl 15 or (a1 ushr 17)) * 5 xor ce) * 3
                        xor b7 xor (b3 and b0.inv()) xor ma)
                ba = (ba shl 1 or (ba ushr 31)).inv() xor a2
                a3 = ((a3 xor (a2 shl 15 or (a2 ushr 17)) * 5 xor cd) * 3
                        xor b8 xor (b4 and b1.inv()) xor mb)
                bb = (bb shl 1 or (bb ushr 31)).inv() xor a3
                a4 = ((a4 xor (a3 shl 15 or (a3 ushr 17)) * 5 xor cc) * 3
                        xor b9 xor (b5 and b2.inv()) xor mc)
                bc = (bc shl 1 or (bc ushr 31)).inv() xor a4
                a5 = ((a5 xor (a4 shl 15 or (a4 ushr 17)) * 5 xor cb) * 3
                        xor ba xor (b6 and b3.inv()) xor md)
                bd = (bd shl 1 or (bd ushr 31)).inv() xor a5
                a6 = ((a6 xor (a5 shl 15 or (a5 ushr 17)) * 5 xor ca) * 3
                        xor bb xor (b7 and b4.inv()) xor me)
                be = (be shl 1 or (be ushr 31)).inv() xor a6
                a7 = ((a7 xor (a6 shl 15 or (a6 ushr 17)) * 5 xor c9) * 3
                        xor bc xor (b8 and b5.inv()) xor mf)
                bf = (bf shl 1 or (bf ushr 31)).inv() xor a7
                a8 = ((a8 xor (a7 shl 15 or (a7 ushr 17)) * 5 xor c8) * 3
                        xor bd xor (b9 and b6.inv()) xor m0)
                b0 = (b0 shl 1 or (b0 ushr 31)).inv() xor a8
                a9 = ((a9 xor (a8 shl 15 or (a8 ushr 17)) * 5 xor c7) * 3
                        xor be xor (ba and b7.inv()) xor m1)
                b1 = (b1 shl 1 or (b1 ushr 31)).inv() xor a9
                aa = ((aa xor (a9 shl 15 or (a9 ushr 17)) * 5 xor c6) * 3
                        xor bf xor (bb and b8.inv()) xor m2)
                b2 = (b2 shl 1 or (b2 ushr 31)).inv() xor aa
                ab = ((ab xor (aa shl 15 or (aa ushr 17)) * 5 xor c5) * 3
                        xor b0 xor (bc and b9.inv()) xor m3)
                b3 = (b3 shl 1 or (b3 ushr 31)).inv() xor ab
                a0 = ((a0 xor (ab shl 15 or (ab ushr 17)) * 5 xor c4) * 3
                        xor b1 xor (bd and ba.inv()) xor m4)
                b4 = (b4 shl 1 or (b4 ushr 31)).inv() xor a0
                a1 = ((a1 xor (a0 shl 15 or (a0 ushr 17)) * 5 xor c3) * 3
                        xor b2 xor (be and bb.inv()) xor m5)
                b5 = (b5 shl 1 or (b5 ushr 31)).inv() xor a1
                a2 = ((a2 xor (a1 shl 15 or (a1 ushr 17)) * 5 xor c2) * 3
                        xor b3 xor (bf and bc.inv()) xor m6)
                b6 = (b6 shl 1 or (b6 ushr 31)).inv() xor a2
                a3 = ((a3 xor (a2 shl 15 or (a2 ushr 17)) * 5 xor c1) * 3
                        xor b4 xor (b0 and bd.inv()) xor m7)
                b7 = (b7 shl 1 or (b7 ushr 31)).inv() xor a3
                a4 = ((a4 xor (a3 shl 15 or (a3 ushr 17)) * 5 xor c0) * 3
                        xor b5 xor (b1 and be.inv()) xor m8)
                b8 = (b8 shl 1 or (b8 ushr 31)).inv() xor a4
                a5 = ((a5 xor (a4 shl 15 or (a4 ushr 17)) * 5 xor cf) * 3
                        xor b6 xor (b2 and bf.inv()) xor m9)
                b9 = (b9 shl 1 or (b9 ushr 31)).inv() xor a5
                a6 = ((a6 xor (a5 shl 15 or (a5 ushr 17)) * 5 xor ce) * 3
                        xor b7 xor (b3 and b0.inv()) xor ma)
                ba = (ba shl 1 or (ba ushr 31)).inv() xor a6
                a7 = ((a7 xor (a6 shl 15 or (a6 ushr 17)) * 5 xor cd) * 3
                        xor b8 xor (b4 and b1.inv()) xor mb)
                bb = (bb shl 1 or (bb ushr 31)).inv() xor a7
                a8 = ((a8 xor (a7 shl 15 or (a7 ushr 17)) * 5 xor cc) * 3
                        xor b9 xor (b5 and b2.inv()) xor mc)
                bc = (bc shl 1 or (bc ushr 31)).inv() xor a8
                a9 = ((a9 xor (a8 shl 15 or (a8 ushr 17)) * 5 xor cb) * 3
                        xor ba xor (b6 and b3.inv()) xor md)
                bd = (bd shl 1 or (bd ushr 31)).inv() xor a9
                aa = ((aa xor (a9 shl 15 or (a9 ushr 17)) * 5 xor ca) * 3
                        xor bb xor (b7 and b4.inv()) xor me)
                be = (be shl 1 or (be ushr 31)).inv() xor aa
                ab = ((ab xor (aa shl 15 or (aa ushr 17)) * 5 xor c9) * 3
                        xor bc xor (b8 and b5.inv()) xor mf)
                bf = (bf shl 1 or (bf ushr 31)).inv() xor ab
                ab += c6 + ca + ce
                aa += c5 + c9 + cd
                a9 += c4 + c8 + cc
                a8 += c3 + c7 + cb
                a7 += c2 + c6 + ca
                a6 += c1 + c5 + c9
                a5 += c0 + c4 + c8
                a4 += cf + c3 + c7
                a3 += ce + c2 + c6
                a2 += cd + c1 + c5
                a1 += cc + c0 + c4
                a0 += cb + cf + c3
                var tmp: Int
                tmp = b0
                b0 = c0 - m0
                c0 = tmp
                tmp = b1
                b1 = c1 - m1
                c1 = tmp
                tmp = b2
                b2 = c2 - m2
                c2 = tmp
                tmp = b3
                b3 = c3 - m3
                c3 = tmp
                tmp = b4
                b4 = c4 - m4
                c4 = tmp
                tmp = b5
                b5 = c5 - m5
                c5 = tmp
                tmp = b6
                b6 = c6 - m6
                c6 = tmp
                tmp = b7
                b7 = c7 - m7
                c7 = tmp
                tmp = b8
                b8 = c8 - m8
                c8 = tmp
                tmp = b9
                b9 = c9 - m9
                c9 = tmp
                tmp = ba
                ba = ca - ma
                ca = tmp
                tmp = bb
                bb = cb - mb
                cb = tmp
                tmp = bc
                bc = cc - mc
                cc = tmp
                tmp = bd
                bd = cd - md
                cd = tmp
                tmp = be
                be = ce - me
                ce = tmp
                tmp = bf
                bf = cf - mf
                cf = tmp
            }
            state[0] = a0
            state[1] = a1
            state[2] = a2
            state[3] = a3
            state[4] = a4
            state[5] = a5
            state[6] = a6
            state[7] = a7
            state[8] = a8
            state[9] = a9
            state[10] = aa
            state[11] = ab
            state[12] = b0
            state[13] = b1
            state[14] = b2
            state[15] = b3
            state[16] = b4
            state[17] = b5
            state[18] = b6
            state[19] = b7
            state[20] = b8
            state[21] = b9
            state[22] = ba
            state[23] = bb
            state[24] = bc
            state[25] = bd
            state[26] = be
            state[27] = bf
            state[28] = c0
            state[29] = c1
            state[30] = c2
            state[31] = c3
            state[32] = c4
            state[33] = c5
            state[34] = c6
            state[35] = c7
            state[36] = c8
            state[37] = c9
            state[38] = ca
            state[39] = cb
            state[40] = cc
            state[41] = cd
            state[42] = ce
            state[43] = cf

            return w
        }
    }
}
