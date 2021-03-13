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

import com.appmattus.crypto.internal.core.circularLeftInt
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 * This class implements SIMD-224 and SIMD-256.
 *
 * @version $Revision: 241 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber", "LargeClass")
internal abstract class SIMDSmallCore<D : SIMDSmallCore<D>> : DigestEngine<D>() {
    private lateinit var state: IntArray
    private lateinit var q: IntArray
    private lateinit var w: IntArray
    private lateinit var tmpState: IntArray
    private lateinit var tA: IntArray

    override val blockLength: Int
        get() = 64

    override fun copyState(dest: D): D {
        state.copyInto(dest.state, 0, 0, 16)
        return super.copyState(dest)
    }

    override fun engineReset() {
        initVal.copyInto(state, 0, 0, 16)
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return the initial value (eight 32-bit words)
     */
    protected abstract val initVal: IntArray

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        val buf = blockBuffer
        if (ptr != 0) {
            for (i in ptr..63) buf[i] = 0x00
            compress(buf, false)
        }
        val count = (blockCount shl 9) + (ptr shl 3).toLong()
        encodeLEInt(count.toInt(), buf, 0)
        encodeLEInt((count shr 32).toInt(), buf, 4)
        for (i in 8..63) buf[i] = 0x00
        compress(buf, true)
        val n = digestLength ushr 2
        for (i in 0 until n) encodeLEInt(state[i], output, outputOffset + (i shl 2))
    }

    override fun doInit() {
        state = IntArray(16)
        q = IntArray(128)
        w = IntArray(32)
        tmpState = IntArray(16)
        tA = IntArray(4)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        compress(data, false)
    }

    @Suppress("LocalVariableName", "VariableNaming", "LongMethod")
    private fun fft32(x: ByteArray, xb: Int, xs: Int, qoff: Int) {
        val xd = xs shl 1
        run {
            var d1_0: Int
            var d1_1: Int
            var d1_2: Int
            var d1_3: Int
            var d1_4: Int
            var d1_5: Int
            var d1_6: Int
            var d1_7: Int
            var d2_0: Int
            var d2_1: Int
            var d2_2: Int
            var d2_3: Int
            var d2_4: Int
            var d2_5: Int
            var d2_6: Int
            var d2_7: Int
            run {
                val x0: Int = x[xb].toInt() and 0xFF
                val x1: Int = x[xb + 2 * xd].toInt() and 0xFF
                val x2: Int = x[xb + 4 * xd].toInt() and 0xFF
                val x3: Int = x[xb + 6 * xd].toInt() and 0xFF
                val a0 = x0 + x2
                val a1 = x0 + (x2 shl 4)
                val a2 = x0 - x2
                val a3 = x0 - (x2 shl 4)
                val b0 = x1 + x3
                val b1 = (((x1 shl 2) + (x3 shl 6) and 0xFF) -
                        ((x1 shl 2) + (x3 shl 6) shr 8))
                val b2 = (x1 shl 4) - (x3 shl 4)
                val b3 = (((x1 shl 6) + (x3 shl 2) and 0xFF) -
                        ((x1 shl 6) + (x3 shl 2) shr 8))
                d1_0 = a0 + b0
                d1_1 = a1 + b1
                d1_2 = a2 + b2
                d1_3 = a3 + b3
                d1_4 = a0 - b0
                d1_5 = a1 - b1
                d1_6 = a2 - b2
                d1_7 = a3 - b3
            }
            run {
                val x0: Int = x[xb + xd].toInt() and 0xFF
                val x1: Int = x[xb + 3 * xd].toInt() and 0xFF
                val x2: Int = x[xb + 5 * xd].toInt() and 0xFF
                val x3: Int = x[xb + 7 * xd].toInt() and 0xFF
                val a0 = x0 + x2
                val a1 = x0 + (x2 shl 4)
                val a2 = x0 - x2
                val a3 = x0 - (x2 shl 4)
                val b0 = x1 + x3
                val b1 = (((x1 shl 2) + (x3 shl 6) and 0xFF) -
                        ((x1 shl 2) + (x3 shl 6) shr 8))
                val b2 = (x1 shl 4) - (x3 shl 4)
                val b3 = (((x1 shl 6) + (x3 shl 2) and 0xFF) -
                        ((x1 shl 6) + (x3 shl 2) shr 8))
                d2_0 = a0 + b0
                d2_1 = a1 + b1
                d2_2 = a2 + b2
                d2_3 = a3 + b3
                d2_4 = a0 - b0
                d2_5 = a1 - b1
                d2_6 = a2 - b2
                d2_7 = a3 - b3
            }
            q[qoff + 0] = d1_0 + d2_0
            q[qoff + 1] = d1_1 + (d2_1 shl 1)
            q[qoff + 2] = d1_2 + (d2_2 shl 2)
            q[qoff + 3] = d1_3 + (d2_3 shl 3)
            q[qoff + 4] = d1_4 + (d2_4 shl 4)
            q[qoff + 5] = d1_5 + (d2_5 shl 5)
            q[qoff + 6] = d1_6 + (d2_6 shl 6)
            q[qoff + 7] = d1_7 + (d2_7 shl 7)
            q[qoff + 8] = d1_0 - d2_0
            q[qoff + 9] = d1_1 - (d2_1 shl 1)
            q[qoff + 10] = d1_2 - (d2_2 shl 2)
            q[qoff + 11] = d1_3 - (d2_3 shl 3)
            q[qoff + 12] = d1_4 - (d2_4 shl 4)
            q[qoff + 13] = d1_5 - (d2_5 shl 5)
            q[qoff + 14] = d1_6 - (d2_6 shl 6)
            q[qoff + 15] = d1_7 - (d2_7 shl 7)
        }
        run {
            var d1_0: Int
            var d1_1: Int
            var d1_2: Int
            var d1_3: Int
            var d1_4: Int
            var d1_5: Int
            var d1_6: Int
            var d1_7: Int
            var d2_0: Int
            var d2_1: Int
            var d2_2: Int
            var d2_3: Int
            var d2_4: Int
            var d2_5: Int
            var d2_6: Int
            var d2_7: Int
            run {
                val x0: Int = x[xb + xs].toInt() and 0xFF
                val x1: Int = x[xb + xs + 2 * xd].toInt() and 0xFF
                val x2: Int = x[xb + xs + 4 * xd].toInt() and 0xFF
                val x3: Int = x[xb + xs + 6 * xd].toInt() and 0xFF
                val a0 = x0 + x2
                val a1 = x0 + (x2 shl 4)
                val a2 = x0 - x2
                val a3 = x0 - (x2 shl 4)
                val b0 = x1 + x3
                val b1 = (((x1 shl 2) + (x3 shl 6) and 0xFF) -
                        ((x1 shl 2) + (x3 shl 6) shr 8))
                val b2 = (x1 shl 4) - (x3 shl 4)
                val b3 = (((x1 shl 6) + (x3 shl 2) and 0xFF) -
                        ((x1 shl 6) + (x3 shl 2) shr 8))
                d1_0 = a0 + b0
                d1_1 = a1 + b1
                d1_2 = a2 + b2
                d1_3 = a3 + b3
                d1_4 = a0 - b0
                d1_5 = a1 - b1
                d1_6 = a2 - b2
                d1_7 = a3 - b3
            }
            run {
                val x0: Int = x[xb + xs + xd].toInt() and 0xFF
                val x1: Int = x[xb + xs + 3 * xd].toInt() and 0xFF
                val x2: Int = x[xb + xs + 5 * xd].toInt() and 0xFF
                val x3: Int = x[xb + xs + 7 * xd].toInt() and 0xFF
                val a0 = x0 + x2
                val a1 = x0 + (x2 shl 4)
                val a2 = x0 - x2
                val a3 = x0 - (x2 shl 4)
                val b0 = x1 + x3
                val b1 = (((x1 shl 2) + (x3 shl 6) and 0xFF) -
                        ((x1 shl 2) + (x3 shl 6) shr 8))
                val b2 = (x1 shl 4) - (x3 shl 4)
                val b3 = (((x1 shl 6) + (x3 shl 2) and 0xFF) -
                        ((x1 shl 6) + (x3 shl 2) shr 8))
                d2_0 = a0 + b0
                d2_1 = a1 + b1
                d2_2 = a2 + b2
                d2_3 = a3 + b3
                d2_4 = a0 - b0
                d2_5 = a1 - b1
                d2_6 = a2 - b2
                d2_7 = a3 - b3
            }
            q[qoff + 16 + 0] = d1_0 + d2_0
            q[qoff + 16 + 1] = d1_1 + (d2_1 shl 1)
            q[qoff + 16 + 2] = d1_2 + (d2_2 shl 2)
            q[qoff + 16 + 3] = d1_3 + (d2_3 shl 3)
            q[qoff + 16 + 4] = d1_4 + (d2_4 shl 4)
            q[qoff + 16 + 5] = d1_5 + (d2_5 shl 5)
            q[qoff + 16 + 6] = d1_6 + (d2_6 shl 6)
            q[qoff + 16 + 7] = d1_7 + (d2_7 shl 7)
            q[qoff + 16 + 8] = d1_0 - d2_0
            q[qoff + 16 + 9] = d1_1 - (d2_1 shl 1)
            q[qoff + 16 + 10] = d1_2 - (d2_2 shl 2)
            q[qoff + 16 + 11] = d1_3 - (d2_3 shl 3)
            q[qoff + 16 + 12] = d1_4 - (d2_4 shl 4)
            q[qoff + 16 + 13] = d1_5 - (d2_5 shl 5)
            q[qoff + 16 + 14] = d1_6 - (d2_6 shl 6)
            q[qoff + 16 + 15] = d1_7 - (d2_7 shl 7)
        }
        var m = q[qoff]
        var n = q[qoff + 16]
        q[qoff] = m + n
        q[qoff + 16] = m - n
        var u = 0
        var v = 0
        while (u < 16) {
            var t: Int
            if (u != 0) {
                m = q[qoff + u + 0]
                n = q[qoff + u + 0 + 16]
                t = ((n * alphaTab[v + 0 * 8] and 0xFFFF) +
                        (n * alphaTab[v + 0 * 8] shr 16))
                q[qoff + u + 0] = m + t
                q[qoff + u + 0 + 16] = m - t
            }
            m = q[qoff + u + 1]
            n = q[qoff + u + 1 + 16]
            t = ((n * alphaTab[v + 1 * 8] and 0xFFFF) +
                    (n * alphaTab[v + 1 * 8] shr 16))
            q[qoff + u + 1] = m + t
            q[qoff + u + 1 + 16] = m - t
            m = q[qoff + u + 2]
            n = q[qoff + u + 2 + 16]
            t = ((n * alphaTab[v + 2 * 8] and 0xFFFF) +
                    (n * alphaTab[v + 2 * 8] shr 16))
            q[qoff + u + 2] = m + t
            q[qoff + u + 2 + 16] = m - t
            m = q[qoff + u + 3]
            n = q[qoff + u + 3 + 16]
            t = ((n * alphaTab[v + 3 * 8] and 0xFFFF) +
                    (n * alphaTab[v + 3 * 8] shr 16))
            q[qoff + u + 3] = m + t
            q[qoff + u + 3 + 16] = m - t
            u += 4
            v += 4 * 8
        }
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    private fun oneRound(isp: Int, p0: Int, p1: Int, p2: Int, p3: Int) {
        var tmp: Int
        tA[0] = circularLeftInt(state[0], p0)
        tA[1] = circularLeftInt(state[1], p0)
        tA[2] = circularLeftInt(state[2], p0)
        tA[3] = circularLeftInt(state[3], p0)
        tmp = (state[12] + w[0] +
                (state[4] xor state[8] and state[0] xor state[8]))
        state[0] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 0] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[1] +
                (state[5] xor state[9] and state[1] xor state[9]))
        state[1] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 0] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[2] +
                (state[6] xor state[10] and state[2] xor state[10]))
        state[2] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 0] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[3] +
                (state[7] xor state[11] and state[3] xor state[11]))
        state[3] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 0] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
        tA[0] = circularLeftInt(state[0], p1)
        tA[1] = circularLeftInt(state[1], p1)
        tA[2] = circularLeftInt(state[2], p1)
        tA[3] = circularLeftInt(state[3], p1)
        tmp = (state[12] + w[4] +
                (state[4] xor state[8] and state[0] xor state[8]))
        state[0] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 1] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[5] +
                (state[5] xor state[9] and state[1] xor state[9]))
        state[1] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 1] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[6] +
                (state[6] xor state[10] and state[2] xor state[10]))
        state[2] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 1] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[7] +
                (state[7] xor state[11] and state[3] xor state[11]))
        state[3] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 1] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
        tA[0] = circularLeftInt(state[0], p2)
        tA[1] = circularLeftInt(state[1], p2)
        tA[2] = circularLeftInt(state[2], p2)
        tA[3] = circularLeftInt(state[3], p2)
        tmp = (state[12] + w[8] +
                (state[4] xor state[8] and state[0] xor state[8]))
        state[0] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 2] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[9] +
                (state[5] xor state[9] and state[1] xor state[9]))
        state[1] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 2] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[10] +
                (state[6] xor state[10] and state[2] xor state[10]))
        state[2] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 2] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[11] +
                (state[7] xor state[11] and state[3] xor state[11]))
        state[3] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 2] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
        tA[0] = circularLeftInt(state[0], p3)
        tA[1] = circularLeftInt(state[1], p3)
        tA[2] = circularLeftInt(state[2], p3)
        tA[3] = circularLeftInt(state[3], p3)
        tmp = (state[12] + w[12] +
                (state[4] xor state[8] and state[0] xor state[8]))
        state[0] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 3] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[13] +
                (state[5] xor state[9] and state[1] xor state[9]))
        state[1] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 3] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[14] +
                (state[6] xor state[10] and state[2] xor state[10]))
        state[2] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 3] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[15] +
                (state[7] xor state[11] and state[3] xor state[11]))
        state[3] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 3] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
        tA[0] = circularLeftInt(state[0], p0)
        tA[1] = circularLeftInt(state[1], p0)
        tA[2] = circularLeftInt(state[2], p0)
        tA[3] = circularLeftInt(state[3], p0)
        tmp = (state[12] + w[16] +
                (state[0] and state[4]
                        or (state[0] or state[4] and state[8])))
        state[0] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 4] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[17] +
                (state[1] and state[5]
                        or (state[1] or state[5] and state[9])))
        state[1] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 4] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[18] +
                (state[2] and state[6]
                        or (state[2] or state[6] and state[10])))
        state[2] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 4] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[19] +
                (state[3] and state[7]
                        or (state[3] or state[7] and state[11])))
        state[3] =
            circularLeftInt(tmp, p1) + tA[pp4k[isp + 4] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
        tA[0] = circularLeftInt(state[0], p1)
        tA[1] = circularLeftInt(state[1], p1)
        tA[2] = circularLeftInt(state[2], p1)
        tA[3] = circularLeftInt(state[3], p1)
        tmp = (state[12] + w[20] +
                (state[0] and state[4]
                        or (state[0] or state[4] and state[8])))
        state[0] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 5] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[21] +
                (state[1] and state[5]
                        or (state[1] or state[5] and state[9])))
        state[1] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 5] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[22] +
                (state[2] and state[6]
                        or (state[2] or state[6] and state[10])))
        state[2] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 5] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[23] +
                (state[3] and state[7]
                        or (state[3] or state[7] and state[11])))
        state[3] =
            circularLeftInt(tmp, p2) + tA[pp4k[isp + 5] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
        tA[0] = circularLeftInt(state[0], p2)
        tA[1] = circularLeftInt(state[1], p2)
        tA[2] = circularLeftInt(state[2], p2)
        tA[3] = circularLeftInt(state[3], p2)
        tmp = (state[12] + w[24] +
                (state[0] and state[4]
                        or (state[0] or state[4] and state[8])))
        state[0] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 6] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[25] +
                (state[1] and state[5]
                        or (state[1] or state[5] and state[9])))
        state[1] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 6] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[26] +
                (state[2] and state[6]
                        or (state[2] or state[6] and state[10])))
        state[2] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 6] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[27] +
                (state[3] and state[7]
                        or (state[3] or state[7] and state[11])))
        state[3] =
            circularLeftInt(tmp, p3) + tA[pp4k[isp + 6] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
        tA[0] = circularLeftInt(state[0], p3)
        tA[1] = circularLeftInt(state[1], p3)
        tA[2] = circularLeftInt(state[2], p3)
        tA[3] = circularLeftInt(state[3], p3)
        tmp = (state[12] + w[28] +
                (state[0] and state[4]
                        or (state[0] or state[4] and state[8])))
        state[0] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 7] xor 0]
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA[0]
        tmp = (state[13] + w[29] +
                (state[1] and state[5]
                        or (state[1] or state[5] and state[9])))
        state[1] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 7] xor 1]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA[1]
        tmp = (state[14] + w[30] +
                (state[2] and state[6]
                        or (state[2] or state[6] and state[10])))
        state[2] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 7] xor 2]
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA[2]
        tmp = (state[15] + w[31] +
                (state[3] and state[7]
                        or (state[3] or state[7] and state[11])))
        state[3] =
            circularLeftInt(tmp, p0) + tA[pp4k[isp + 7] xor 3]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA[3]
    }

    @Suppress("JoinDeclarationAndAssignment", "ComplexMethod", "LongMethod")
    private fun compress(x: ByteArray, last: Boolean) {
        fft32(x, 0 + 1 * 0, 1 shl 2, 0 + 0)
        fft32(x, 0 + 1 * 2, 1 shl 2, 0 + 32)
        var m = q[0]
        var n = q[0 + 32]
        q[0] = m + n
        q[0 + 32] = m - n
        run {
            var u = 0
            var v = 0
            while (u < 32) {
                var t: Int
                if (u != 0) {
                    m = q[0 + u + 0]
                    n = q[0 + u + 0 + 32]
                    t = ((n * alphaTab[v + 0 * 4] and 0xFFFF) +
                            (n * alphaTab[v + 0 * 4] shr 16))
                    q[0 + u + 0] = m + t
                    q[0 + u + 0 + 32] = m - t
                }
                m = q[0 + u + 1]
                n = q[0 + u + 1 + 32]
                t = ((n * alphaTab[v + 1 * 4] and 0xFFFF) +
                        (n * alphaTab[v + 1 * 4] shr 16))
                q[0 + u + 1] = m + t
                q[0 + u + 1 + 32] = m - t
                m = q[0 + u + 2]
                n = q[0 + u + 2 + 32]
                t = ((n * alphaTab[v + 2 * 4] and 0xFFFF) +
                        (n * alphaTab[v + 2 * 4] shr 16))
                q[0 + u + 2] = m + t
                q[0 + u + 2 + 32] = m - t
                m = q[0 + u + 3]
                n = q[0 + u + 3 + 32]
                t = ((n * alphaTab[v + 3 * 4] and 0xFFFF) +
                        (n * alphaTab[v + 3 * 4] shr 16))
                q[0 + u + 3] = m + t
                q[0 + u + 3 + 32] = m - t
                u += 4
                v += 4 * 4
            }
        }
        fft32(x, 0 + 1 * 1, 1 shl 2, 0 + 64)
        fft32(x, 0 + 1 * 3, 1 shl 2, 0 + 96)
        m = q[0 + 64]
        n = q[0 + 64 + 32]
        q[0 + 64] = m + n
        q[0 + 64 + 32] = m - n
        run {
            var u = 0
            var v = 0
            while (u < 32) {
                var t: Int
                if (u != 0) {
                    m = q[0 + 64 + u + 0]
                    n = q[0 + 64 + u + 0 + 32]
                    t = ((n * alphaTab[v + 0 * 4] and 0xFFFF) +
                            (n * alphaTab[v + 0 * 4] shr 16))
                    q[0 + 64 + u + 0] = m + t
                    q[0 + 64 + u + 0 + 32] = m - t
                }
                m = q[0 + 64 + u + 1]
                n = q[0 + 64 + u + 1 + 32]
                t = ((n * alphaTab[v + 1 * 4] and 0xFFFF) +
                        (n * alphaTab[v + 1 * 4] shr 16))
                q[0 + 64 + u + 1] = m + t
                q[0 + 64 + u + 1 + 32] = m - t
                m = q[0 + 64 + u + 2]
                n = q[0 + 64 + u + 2 + 32]
                t = ((n * alphaTab[v + 2 * 4] and 0xFFFF) +
                        (n * alphaTab[v + 2 * 4] shr 16))
                q[0 + 64 + u + 2] = m + t
                q[0 + 64 + u + 2 + 32] = m - t
                m = q[0 + 64 + u + 3]
                n = q[0 + 64 + u + 3 + 32]
                t = ((n * alphaTab[v + 3 * 4] and 0xFFFF) +
                        (n * alphaTab[v + 3 * 4] shr 16))
                q[0 + 64 + u + 3] = m + t
                q[0 + 64 + u + 3 + 32] = m - t
                u += 4
                v += 4 * 4
            }
        }
        m = q[0]
        n = q[0 + 64]
        q[0] = m + n
        q[0 + 64] = m - n
        run {
            var u = 0
            var v = 0
            while (u < 64) {
                var t: Int
                if (u != 0) {
                    m = q[0 + u + 0]
                    n = q[0 + u + 0 + 64]
                    t = ((n * alphaTab[v + 0 * 2] and 0xFFFF) +
                            (n * alphaTab[v + 0 * 2] shr 16))
                    q[0 + u + 0] = m + t
                    q[0 + u + 0 + 64] = m - t
                }
                m = q[0 + u + 1]
                n = q[0 + u + 1 + 64]
                t = ((n * alphaTab[v + 1 * 2] and 0xFFFF) +
                        (n * alphaTab[v + 1 * 2] shr 16))
                q[0 + u + 1] = m + t
                q[0 + u + 1 + 64] = m - t
                m = q[0 + u + 2]
                n = q[0 + u + 2 + 64]
                t = ((n * alphaTab[v + 2 * 2] and 0xFFFF) +
                        (n * alphaTab[v + 2 * 2] shr 16))
                q[0 + u + 2] = m + t
                q[0 + u + 2 + 64] = m - t
                m = q[0 + u + 3]
                n = q[0 + u + 3 + 64]
                t = ((n * alphaTab[v + 3 * 2] and 0xFFFF) +
                        (n * alphaTab[v + 3 * 2] shr 16))
                q[0 + u + 3] = m + t
                q[0 + u + 3 + 64] = m - t
                u += 4
                v += 4 * 2
            }
        }
        if (last) {
            for (i in 0..127) {
                var tq: Int
                tq = q[i] + yoffF[i]
                tq = (tq and 0xFFFF) + (tq shr 16)
                tq = (tq and 0xFF) - (tq shr 8)
                tq = (tq and 0xFF) - (tq shr 8)
                q[i] = if (tq <= 128) tq else tq - 257
            }
        } else {
            for (i in 0..127) {
                var tq: Int
                tq = q[i] + yoffN[i]
                tq = (tq and 0xFFFF) + (tq shr 16)
                tq = (tq and 0xFF) - (tq shr 8)
                tq = (tq and 0xFF) - (tq shr 8)
                q[i] = if (tq <= 128) tq else tq - 257
            }
        }
        state.copyInto(tmpState, 0, 0, 16)
        var i = 0
        while (i < 16) {
            state[i + 0] = state[i + 0] xor decodeLEInt(x, 4 * (i + 0))
            state[i + 1] = state[i + 1] xor decodeLEInt(x, 4 * (i + 1))
            state[i + 2] = state[i + 2] xor decodeLEInt(x, 4 * (i + 2))
            state[i + 3] = state[i + 3] xor decodeLEInt(x, 4 * (i + 3))
            i += 4
        }
        run {
            var u = 0
            while (u < 32) {
                val v: Int = wsp[(u shr 2) + 0]
                w[u + 0] = ((q[v + 2 * 0 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 0 + 1] * 185 shl 16))
                w[u + 1] = ((q[v + 2 * 1 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 1 + 1] * 185 shl 16))
                w[u + 2] = ((q[v + 2 * 2 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 2 + 1] * 185 shl 16))
                w[u + 3] = ((q[v + 2 * 3 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 3 + 1] * 185 shl 16))
                u += 4
            }
        }
        oneRound(0, 3, 23, 17, 27)
        run {
            var u = 0
            while (u < 32) {
                val v: Int = wsp[(u shr 2) + 8]
                w[u + 0] = ((q[v + 2 * 0 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 0 + 1] * 185 shl 16))
                w[u + 1] = ((q[v + 2 * 1 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 1 + 1] * 185 shl 16))
                w[u + 2] = ((q[v + 2 * 2 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 2 + 1] * 185 shl 16))
                w[u + 3] = ((q[v + 2 * 3 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 3 + 1] * 185 shl 16))
                u += 4
            }
        }
        oneRound(2, 28, 19, 22, 7)
        run {
            var u = 0
            while (u < 32) {
                val v: Int = wsp[(u shr 2) + 16]
                w[u + 0] = ((q[v + 2 * 0 + -128] * 233 and 0xFFFF) +
                        (q[v + 2 * 0 + -64] * 233 shl 16))
                w[u + 1] = ((q[v + 2 * 1 + -128] * 233 and 0xFFFF) +
                        (q[v + 2 * 1 + -64] * 233 shl 16))
                w[u + 2] = ((q[v + 2 * 2 + -128] * 233 and 0xFFFF) +
                        (q[v + 2 * 2 + -64] * 233 shl 16))
                w[u + 3] = ((q[v + 2 * 3 + -128] * 233 and 0xFFFF) +
                        (q[v + 2 * 3 + -64] * 233 shl 16))
                u += 4
            }
        }
        oneRound(1, 29, 9, 15, 5)
        var u = 0
        while (u < 32) {
            val v: Int = wsp[(u shr 2) + 24]
            w[u + 0] = ((q[v + 2 * 0 + -191] * 233 and 0xFFFF) +
                    (q[v + 2 * 0 + -127] * 233 shl 16))
            w[u + 1] = ((q[v + 2 * 1 + -191] * 233 and 0xFFFF) +
                    (q[v + 2 * 1 + -127] * 233 shl 16))
            w[u + 2] = ((q[v + 2 * 2 + -191] * 233 and 0xFFFF) +
                    (q[v + 2 * 2 + -127] * 233 shl 16))
            w[u + 3] = ((q[v + 2 * 3 + -191] * 233 and 0xFFFF) +
                    (q[v + 2 * 3 + -127] * 233 shl 16))
            u += 4
        }
        oneRound(0, 4, 13, 10, 25)
        run {
            val tA0: Int = circularLeftInt(state[0], 4)
            val tA1: Int = circularLeftInt(state[1], 4)
            val tA2: Int = circularLeftInt(state[2], 4)
            val tA3: Int = circularLeftInt(state[3], 4)
            var tmp: Int
            tmp = state[12] + tmpState[0] + ((state[4]
                    xor state[8]) and state[0] xor state[8])
            state[0] = circularLeftInt(tmp, 13) + tA3
            state[12] = state[8]
            state[8] = state[4]
            state[4] = tA0
            tmp = state[13] + tmpState[1] + ((state[5]
                    xor state[9]) and state[1] xor state[9])
            state[1] = circularLeftInt(tmp, 13) + tA2
            state[13] = state[9]
            state[9] = state[5]
            state[5] = tA1
            tmp = state[14] + tmpState[2] + ((state[6]
                    xor state[10]) and state[2] xor state[10])
            state[2] = circularLeftInt(tmp, 13) + tA1
            state[14] = state[10]
            state[10] = state[6]
            state[6] = tA2
            tmp = state[15] + tmpState[3] + ((state[7]
                    xor state[11]) and state[3] xor state[11])
            state[3] = circularLeftInt(tmp, 13) + tA0
            state[15] = state[11]
            state[11] = state[7]
            state[7] = tA3
        }
        run {
            val tA0: Int = circularLeftInt(state[0], 13)
            val tA1: Int = circularLeftInt(state[1], 13)
            val tA2: Int = circularLeftInt(state[2], 13)
            val tA3: Int = circularLeftInt(state[3], 13)
            var tmp: Int
            tmp = state[12] + tmpState[4] + ((state[4]
                    xor state[8]) and state[0] xor state[8])
            state[0] = circularLeftInt(tmp, 10) + tA1
            state[12] = state[8]
            state[8] = state[4]
            state[4] = tA0
            tmp = state[13] + tmpState[5] + ((state[5]
                    xor state[9]) and state[1] xor state[9])
            state[1] = circularLeftInt(tmp, 10) + tA0
            state[13] = state[9]
            state[9] = state[5]
            state[5] = tA1
            tmp = state[14] + tmpState[6] + ((state[6]
                    xor state[10]) and state[2] xor state[10])
            state[2] = circularLeftInt(tmp, 10) + tA3
            state[14] = state[10]
            state[10] = state[6]
            state[6] = tA2
            tmp = state[15] + tmpState[7] + ((state[7]
                    xor state[11]) and state[3] xor state[11])
            state[3] = circularLeftInt(tmp, 10) + tA2
            state[15] = state[11]
            state[11] = state[7]
            state[7] = tA3
        }
        run {
            val tA0: Int = circularLeftInt(state[0], 10)
            val tA1: Int = circularLeftInt(state[1], 10)
            val tA2: Int = circularLeftInt(state[2], 10)
            val tA3: Int = circularLeftInt(state[3], 10)
            var tmp: Int
            tmp = state[12] + tmpState[8] + ((state[4]
                    xor state[8]) and state[0] xor state[8])
            state[0] = circularLeftInt(tmp, 25) + tA2
            state[12] = state[8]
            state[8] = state[4]
            state[4] = tA0
            tmp = state[13] + tmpState[9] + ((state[5]
                    xor state[9]) and state[1] xor state[9])
            state[1] = circularLeftInt(tmp, 25) + tA3
            state[13] = state[9]
            state[9] = state[5]
            state[5] = tA1
            tmp = state[14] + tmpState[10] + ((state[6]
                    xor state[10]) and state[2] xor state[10])
            state[2] = circularLeftInt(tmp, 25) + tA0
            state[14] = state[10]
            state[10] = state[6]
            state[6] = tA2
            tmp = state[15] + tmpState[11] + ((state[7]
                    xor state[11]) and state[3] xor state[11])
            state[3] = circularLeftInt(tmp, 25) + tA1
            state[15] = state[11]
            state[11] = state[7]
            state[7] = tA3
        }
        run {
            val tA0: Int = circularLeftInt(state[0], 25)
            val tA1: Int = circularLeftInt(state[1], 25)
            val tA2: Int = circularLeftInt(state[2], 25)
            val tA3: Int = circularLeftInt(state[3], 25)
            var tmp: Int
            tmp = state[12] + tmpState[12] + ((state[4]
                    xor state[8]) and state[0] xor state[8])
            state[0] = circularLeftInt(tmp, 4) + tA3
            state[12] = state[8]
            state[8] = state[4]
            state[4] = tA0
            tmp = state[13] + tmpState[13] + ((state[5]
                    xor state[9]) and state[1] xor state[9])
            state[1] = circularLeftInt(tmp, 4) + tA2
            state[13] = state[9]
            state[9] = state[5]
            state[5] = tA1
            tmp = state[14] + tmpState[14] + ((state[6]
                    xor state[10]) and state[2] xor state[10])
            state[2] = circularLeftInt(tmp, 4) + tA1
            state[14] = state[10]
            state[10] = state[6]
            state[6] = tA2
            tmp = state[15] + tmpState[15] + ((state[7]
                    xor state[11]) and state[3] xor state[11])
            state[3] = circularLeftInt(tmp, 4) + tA0
            state[15] = state[11]
            state[11] = state[7]
            state[7] = tA3
        }
    }

    override fun toString(): String {
        return "SIMD-" + (digestLength shl 3)
    }

    companion object {

        private val alphaTab = intArrayOf(
            1, 41, 139, 45, 46, 87, 226, 14, 60, 147, 116, 130,
            190, 80, 196, 69, 2, 82, 21, 90, 92, 174, 195, 28,
            120, 37, 232, 3, 123, 160, 135, 138, 4, 164, 42, 180,
            184, 91, 133, 56, 240, 74, 207, 6, 246, 63, 13, 19,
            8, 71, 84, 103, 111, 182, 9, 112, 223, 148, 157, 12,
            235, 126, 26, 38, 16, 142, 168, 206, 222, 107, 18, 224,
            189, 39, 57, 24, 213, 252, 52, 76, 32, 27, 79, 155,
            187, 214, 36, 191, 121, 78, 114, 48, 169, 247, 104, 152,
            64, 54, 158, 53, 117, 171, 72, 125, 242, 156, 228, 96,
            81, 237, 208, 47, 128, 108, 59, 106, 234, 85, 144, 250,
            227, 55, 199, 192, 162, 217, 159, 94, 256, 216, 118, 212,
            211, 170, 31, 243, 197, 110, 141, 127, 67, 177, 61, 188,
            255, 175, 236, 167, 165, 83, 62, 229, 137, 220, 25, 254,
            134, 97, 122, 119, 253, 93, 215, 77, 73, 166, 124, 201,
            17, 183, 50, 251, 11, 194, 244, 238, 249, 186, 173, 154,
            146, 75, 248, 145, 34, 109, 100, 245, 22, 131, 231, 219,
            241, 115, 89, 51, 35, 150, 239, 33, 68, 218, 200, 233,
            44, 5, 205, 181, 225, 230, 178, 102, 70, 43, 221, 66,
            136, 179, 143, 209, 88, 10, 153, 105, 193, 203, 99, 204,
            140, 86, 185, 132, 15, 101, 29, 161, 176, 20, 49, 210,
            129, 149, 198, 151, 23, 172, 113, 7, 30, 202, 58, 65,
            95, 40, 98, 163
        )
        private val yoffN = intArrayOf(
            1, 98, 95, 58, 30, 113, 23, 198, 129, 49, 176, 29,
            15, 185, 140, 99, 193, 153, 88, 143, 136, 221, 70, 178,
            225, 205, 44, 200, 68, 239, 35, 89, 241, 231, 22, 100,
            34, 248, 146, 173, 249, 244, 11, 50, 17, 124, 73, 215,
            253, 122, 134, 25, 137, 62, 165, 236, 255, 61, 67, 141,
            197, 31, 211, 118, 256, 159, 162, 199, 227, 144, 234, 59,
            128, 208, 81, 228, 242, 72, 117, 158, 64, 104, 169, 114,
            121, 36, 187, 79, 32, 52, 213, 57, 189, 18, 222, 168,
            16, 26, 235, 157, 223, 9, 111, 84, 8, 13, 246, 207,
            240, 133, 184, 42, 4, 135, 123, 232, 120, 195, 92, 21,
            2, 196, 190, 116, 60, 226, 46, 139
        )
        private val yoffF = intArrayOf(
            2, 156, 118, 107, 45, 212, 111, 162, 97, 249, 211, 3,
            49, 101, 151, 223, 189, 178, 253, 204, 76, 82, 232, 65,
            96, 176, 161, 47, 189, 61, 248, 107, 0, 131, 133, 113,
            17, 33, 12, 111, 251, 103, 57, 148, 47, 65, 249, 143,
            189, 8, 204, 230, 205, 151, 187, 227, 247, 111, 140, 6,
            77, 10, 21, 149, 255, 101, 139, 150, 212, 45, 146, 95,
            160, 8, 46, 254, 208, 156, 106, 34, 68, 79, 4, 53,
            181, 175, 25, 192, 161, 81, 96, 210, 68, 196, 9, 150,
            0, 126, 124, 144, 240, 224, 245, 146, 6, 154, 200, 109,
            210, 192, 8, 114, 68, 249, 53, 27, 52, 106, 70, 30,
            10, 146, 117, 251, 180, 247, 236, 108
        )
        private val pp4k = intArrayOf(
            1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2
        )
        private val wsp = intArrayOf(
            4 shl 3, 6 shl 3, 0 shl 3, 2 shl 3,
            7 shl 3, 5 shl 3, 3 shl 3, 1 shl 3,
            15 shl 3, 11 shl 3, 12 shl 3, 8 shl 3,
            9 shl 3, 13 shl 3, 10 shl 3, 14 shl 3,
            17 shl 3, 18 shl 3, 23 shl 3, 20 shl 3,
            22 shl 3, 21 shl 3, 16 shl 3, 19 shl 3,
            30 shl 3, 24 shl 3, 25 shl 3, 31 shl 3,
            27 shl 3, 29 shl 3, 28 shl 3, 26 shl 3
        )
    }
}
