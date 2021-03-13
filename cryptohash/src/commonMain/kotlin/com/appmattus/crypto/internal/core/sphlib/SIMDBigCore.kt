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
 * This class implements SIMD-384 and SIMD-512.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber", "LargeClass")
internal abstract class SIMDBigCore<D : SIMDBigCore<D>> : DigestEngine<D>() {
    private lateinit var state: IntArray
    private lateinit var q: IntArray
    private lateinit var w: IntArray
    private lateinit var tmpState: IntArray
    private lateinit var tA: IntArray

    override val blockLength: Int
        get() = 128

    override fun copyState(dest: D): D {
        state.copyInto(dest.state, 0, 0, 32)
        return super.copyState(dest)
    }

    override fun engineReset() {
        val iv = initVal
        iv.copyInto(state, 0, 0, 32)
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return the initial value
     */
    protected abstract val initVal: IntArray

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        val buf = blockBuffer
        if (ptr != 0) {
            for (i in ptr..127) buf[i] = 0x00
            compress(buf, false)
        }
        val count = (blockCount shl 10) + (ptr shl 3).toLong()
        encodeLEInt(count.toInt(), buf, 0)
        encodeLEInt((count shr 32).toInt(), buf, 4)
        for (i in 8..127) buf[i] = 0x00
        compress(buf, true)
        val n = digestLength ushr 2
        for (i in 0 until n) encodeLEInt(state[i], output, outputOffset + (i shl 2))
    }

    override fun doInit() {
        state = IntArray(32)
        q = IntArray(256)
        w = IntArray(64)
        tmpState = IntArray(32)
        tA = IntArray(8)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        compress(data, false)
    }

    @Suppress("LocalVariableName", "VariableNaming", "ComplexMethod", "LongMethod")
    private fun fft64(x: ByteArray, xb: Int, xs: Int, qoff: Int) {
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
                val x0: Int = x[xb + 0 * xd].toInt() and 0xFF
                val x1: Int = x[xb + 4 * xd].toInt() and 0xFF
                val x2: Int = x[xb + 8 * xd].toInt() and 0xFF
                val x3: Int = x[xb + 12 * xd].toInt() and 0xFF
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
                val x0: Int = x[xb + 2 * xd].toInt() and 0xFF
                val x1: Int = x[xb + 6 * xd].toInt() and 0xFF
                val x2: Int = x[xb + 10 * xd].toInt() and 0xFF
                val x3: Int = x[xb + 14 * xd].toInt() and 0xFF
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
                val x0: Int = x[xb + 1 * xd].toInt() and 0xFF
                val x1: Int = x[xb + 5 * xd].toInt() and 0xFF
                val x2: Int = x[xb + 9 * xd].toInt() and 0xFF
                val x3: Int = x[xb + 13 * xd].toInt() and 0xFF
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
                val x0: Int = x[xb + 3 * xd].toInt() and 0xFF
                val x1: Int = x[xb + 7 * xd].toInt() and 0xFF
                val x2: Int = x[xb + 11 * xd].toInt() and 0xFF
                val x3: Int = x[xb + 15 * xd].toInt() and 0xFF
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
        run {
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
                val x0: Int = x[xb + xs + 0 * xd].toInt() and 0xFF
                val x1: Int = x[xb + xs + 4 * xd].toInt() and 0xFF
                val x2: Int = x[xb + xs + 8 * xd].toInt() and 0xFF
                val x3: Int = x[xb + xs + 12 * xd].toInt() and 0xFF
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
                val x0: Int = x[xb + xs + 2 * xd].toInt() and 0xFF
                val x1: Int = x[xb + xs + 6 * xd].toInt() and 0xFF
                val x2: Int = x[xb + xs + 10 * xd].toInt() and 0xFF
                val x3: Int = x[xb + xs + 14 * xd].toInt() and 0xFF
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
            q[qoff + 32 + 0] = d1_0 + d2_0
            q[qoff + 32 + 1] = d1_1 + (d2_1 shl 1)
            q[qoff + 32 + 2] = d1_2 + (d2_2 shl 2)
            q[qoff + 32 + 3] = d1_3 + (d2_3 shl 3)
            q[qoff + 32 + 4] = d1_4 + (d2_4 shl 4)
            q[qoff + 32 + 5] = d1_5 + (d2_5 shl 5)
            q[qoff + 32 + 6] = d1_6 + (d2_6 shl 6)
            q[qoff + 32 + 7] = d1_7 + (d2_7 shl 7)
            q[qoff + 32 + 8] = d1_0 - d2_0
            q[qoff + 32 + 9] = d1_1 - (d2_1 shl 1)
            q[qoff + 32 + 10] = d1_2 - (d2_2 shl 2)
            q[qoff + 32 + 11] = d1_3 - (d2_3 shl 3)
            q[qoff + 32 + 12] = d1_4 - (d2_4 shl 4)
            q[qoff + 32 + 13] = d1_5 - (d2_5 shl 5)
            q[qoff + 32 + 14] = d1_6 - (d2_6 shl 6)
            q[qoff + 32 + 15] = d1_7 - (d2_7 shl 7)
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
                val x0: Int = x[xb + xs + 1 * xd].toInt() and 0xFF
                val x1: Int = x[xb + xs + 5 * xd].toInt() and 0xFF
                val x2: Int = x[xb + xs + 9 * xd].toInt() and 0xFF
                val x3: Int = x[xb + xs + 13 * xd].toInt() and 0xFF
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
                val x0: Int = x[xb + xs + 3 * xd].toInt() and 0xFF
                val x1: Int = x[xb + xs + 7 * xd].toInt() and 0xFF
                val x2: Int = x[xb + xs + 11 * xd].toInt() and 0xFF
                val x3: Int = x[xb + xs + 15 * xd].toInt() and 0xFF
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
            q[qoff + 32 + 16 + 0] = d1_0 + d2_0
            q[qoff + 32 + 16 + 1] = d1_1 + (d2_1 shl 1)
            q[qoff + 32 + 16 + 2] = d1_2 + (d2_2 shl 2)
            q[qoff + 32 + 16 + 3] = d1_3 + (d2_3 shl 3)
            q[qoff + 32 + 16 + 4] = d1_4 + (d2_4 shl 4)
            q[qoff + 32 + 16 + 5] = d1_5 + (d2_5 shl 5)
            q[qoff + 32 + 16 + 6] = d1_6 + (d2_6 shl 6)
            q[qoff + 32 + 16 + 7] = d1_7 + (d2_7 shl 7)
            q[qoff + 32 + 16 + 8] = d1_0 - d2_0
            q[qoff + 32 + 16 + 9] = d1_1 - (d2_1 shl 1)
            q[qoff + 32 + 16 + 10] = d1_2 - (d2_2 shl 2)
            q[qoff + 32 + 16 + 11] = d1_3 - (d2_3 shl 3)
            q[qoff + 32 + 16 + 12] = d1_4 - (d2_4 shl 4)
            q[qoff + 32 + 16 + 13] = d1_5 - (d2_5 shl 5)
            q[qoff + 32 + 16 + 14] = d1_6 - (d2_6 shl 6)
            q[qoff + 32 + 16 + 15] = d1_7 - (d2_7 shl 7)
        }
        m = q[qoff + 32]
        n = q[qoff + 32 + 16]
        q[qoff + 32] = m + n
        q[qoff + 32 + 16] = m - n
        run {
            var u = 0
            var v = 0
            while (u < 16) {
                var t: Int
                if (u != 0) {
                    m = q[qoff + 32 + u + 0]
                    n = q[qoff + 32 + u + 0 + 16]
                    t = ((n * alphaTab[v + 0 * 8] and 0xFFFF) +
                            (n * alphaTab[v + 0 * 8] shr 16))
                    q[qoff + 32 + u + 0] = m + t
                    q[qoff + 32 + u + 0 + 16] = m - t
                }
                m = q[qoff + 32 + u + 1]
                n = q[qoff + 32 + u + 1 + 16]
                t = ((n * alphaTab[v + 1 * 8] and 0xFFFF) +
                        (n * alphaTab[v + 1 * 8] shr 16))
                q[qoff + 32 + u + 1] = m + t
                q[qoff + 32 + u + 1 + 16] = m - t
                m = q[qoff + 32 + u + 2]
                n = q[qoff + 32 + u + 2 + 16]
                t = ((n * alphaTab[v + 2 * 8] and 0xFFFF) +
                        (n * alphaTab[v + 2 * 8] shr 16))
                q[qoff + 32 + u + 2] = m + t
                q[qoff + 32 + u + 2 + 16] = m - t
                m = q[qoff + 32 + u + 3]
                n = q[qoff + 32 + u + 3 + 16]
                t = ((n * alphaTab[v + 3 * 8] and 0xFFFF) +
                        (n * alphaTab[v + 3 * 8] shr 16))
                q[qoff + 32 + u + 3] = m + t
                q[qoff + 32 + u + 3 + 16] = m - t
                u += 4
                v += 4 * 8
            }
        }
        m = q[qoff]
        n = q[qoff + 32]
        q[qoff] = m + n
        q[qoff + 32] = m - n
        var u = 0
        var v = 0
        while (u < 32) {
            var t: Int
            if (u != 0) {
                m = q[qoff + u + 0]
                n = q[qoff + u + 0 + 32]
                t = ((n * alphaTab[v + 0 * 4] and 0xFFFF) +
                        (n * alphaTab[v + 0 * 4] shr 16))
                q[qoff + u + 0] = m + t
                q[qoff + u + 0 + 32] = m - t
            }
            m = q[qoff + u + 1]
            n = q[qoff + u + 1 + 32]
            t = ((n * alphaTab[v + 1 * 4] and 0xFFFF) +
                    (n * alphaTab[v + 1 * 4] shr 16))
            q[qoff + u + 1] = m + t
            q[qoff + u + 1 + 32] = m - t
            m = q[qoff + u + 2]
            n = q[qoff + u + 2 + 32]
            t = ((n * alphaTab[v + 2 * 4] and 0xFFFF) +
                    (n * alphaTab[v + 2 * 4] shr 16))
            q[qoff + u + 2] = m + t
            q[qoff + u + 2 + 32] = m - t
            m = q[qoff + u + 3]
            n = q[qoff + u + 3 + 32]
            t = ((n * alphaTab[v + 3 * 4] and 0xFFFF) +
                    (n * alphaTab[v + 3 * 4] shr 16))
            q[qoff + u + 3] = m + t
            q[qoff + u + 3 + 32] = m - t
            u += 4
            v += 4 * 4
        }
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    private fun oneRound(isp: Int, p0: Int, p1: Int, p2: Int, p3: Int) {
        var tmp: Int
        tA[0] = circularLeftInt(state[0], p0)
        tA[1] = circularLeftInt(state[1], p0)
        tA[2] = circularLeftInt(state[2], p0)
        tA[3] = circularLeftInt(state[3], p0)
        tA[4] = circularLeftInt(state[4], p0)
        tA[5] = circularLeftInt(state[5], p0)
        tA[6] = circularLeftInt(state[6], p0)
        tA[7] = circularLeftInt(state[7], p0)
        tmp = (state[24] + w[0] +
                (state[8] xor state[16] and state[0] xor state[16]))
        state[0] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[1] +
                (state[9] xor state[17] and state[1] xor state[17]))
        state[1] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[2] +
                (state[10] xor state[18] and state[2] xor state[18]))
        state[2] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[3] +
                (state[11] xor state[19] and state[3] xor state[19]))
        state[3] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[4] +
                (state[12] xor state[20] and state[4] xor state[20]))
        state[4] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[5] +
                (state[13] xor state[21] and state[5] xor state[21]))
        state[5] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[6] +
                (state[14] xor state[22] and state[6] xor state[22]))
        state[6] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[7] +
                (state[15] xor state[23] and state[7] xor state[23]))
        state[7] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 0] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
        tA[0] = circularLeftInt(state[0], p1)
        tA[1] = circularLeftInt(state[1], p1)
        tA[2] = circularLeftInt(state[2], p1)
        tA[3] = circularLeftInt(state[3], p1)
        tA[4] = circularLeftInt(state[4], p1)
        tA[5] = circularLeftInt(state[5], p1)
        tA[6] = circularLeftInt(state[6], p1)
        tA[7] = circularLeftInt(state[7], p1)
        tmp = (state[24] + w[8] +
                (state[8] xor state[16] and state[0] xor state[16]))
        state[0] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[9] +
                (state[9] xor state[17] and state[1] xor state[17]))
        state[1] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[10] +
                (state[10] xor state[18] and state[2] xor state[18]))
        state[2] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[11] +
                (state[11] xor state[19] and state[3] xor state[19]))
        state[3] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[12] +
                (state[12] xor state[20] and state[4] xor state[20]))
        state[4] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[13] +
                (state[13] xor state[21] and state[5] xor state[21]))
        state[5] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[14] +
                (state[14] xor state[22] and state[6] xor state[22]))
        state[6] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[15] +
                (state[15] xor state[23] and state[7] xor state[23]))
        state[7] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 1] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
        tA[0] = circularLeftInt(state[0], p2)
        tA[1] = circularLeftInt(state[1], p2)
        tA[2] = circularLeftInt(state[2], p2)
        tA[3] = circularLeftInt(state[3], p2)
        tA[4] = circularLeftInt(state[4], p2)
        tA[5] = circularLeftInt(state[5], p2)
        tA[6] = circularLeftInt(state[6], p2)
        tA[7] = circularLeftInt(state[7], p2)
        tmp = (state[24] + w[16] +
                (state[8] xor state[16] and state[0] xor state[16]))
        state[0] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[17] +
                (state[9] xor state[17] and state[1] xor state[17]))
        state[1] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[18] +
                (state[10] xor state[18] and state[2] xor state[18]))
        state[2] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[19] +
                (state[11] xor state[19] and state[3] xor state[19]))
        state[3] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[20] +
                (state[12] xor state[20] and state[4] xor state[20]))
        state[4] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[21] +
                (state[13] xor state[21] and state[5] xor state[21]))
        state[5] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[22] +
                (state[14] xor state[22] and state[6] xor state[22]))
        state[6] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[23] +
                (state[15] xor state[23] and state[7] xor state[23]))
        state[7] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 2] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
        tA[0] = circularLeftInt(state[0], p3)
        tA[1] = circularLeftInt(state[1], p3)
        tA[2] = circularLeftInt(state[2], p3)
        tA[3] = circularLeftInt(state[3], p3)
        tA[4] = circularLeftInt(state[4], p3)
        tA[5] = circularLeftInt(state[5], p3)
        tA[6] = circularLeftInt(state[6], p3)
        tA[7] = circularLeftInt(state[7], p3)
        tmp = (state[24] + w[24] +
                (state[8] xor state[16] and state[0] xor state[16]))
        state[0] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[25] +
                (state[9] xor state[17] and state[1] xor state[17]))
        state[1] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[26] +
                (state[10] xor state[18] and state[2] xor state[18]))
        state[2] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[27] +
                (state[11] xor state[19] and state[3] xor state[19]))
        state[3] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[28] +
                (state[12] xor state[20] and state[4] xor state[20]))
        state[4] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[29] +
                (state[13] xor state[21] and state[5] xor state[21]))
        state[5] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[30] +
                (state[14] xor state[22] and state[6] xor state[22]))
        state[6] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[31] +
                (state[15] xor state[23] and state[7] xor state[23]))
        state[7] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 3] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
        tA[0] = circularLeftInt(state[0], p0)
        tA[1] = circularLeftInt(state[1], p0)
        tA[2] = circularLeftInt(state[2], p0)
        tA[3] = circularLeftInt(state[3], p0)
        tA[4] = circularLeftInt(state[4], p0)
        tA[5] = circularLeftInt(state[5], p0)
        tA[6] = circularLeftInt(state[6], p0)
        tA[7] = circularLeftInt(state[7], p0)
        tmp = (state[24] + w[32] +
                (state[0] and state[8]
                        or (state[0] or state[8] and state[16])))
        state[0] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[33] +
                (state[1] and state[9]
                        or (state[1] or state[9] and state[17])))
        state[1] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[34] +
                (state[2] and state[10]
                        or (state[2] or state[10] and state[18])))
        state[2] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[35] +
                (state[3] and state[11]
                        or (state[3] or state[11] and state[19])))
        state[3] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[36] +
                (state[4] and state[12]
                        or (state[4] or state[12] and state[20])))
        state[4] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[37] +
                (state[5] and state[13]
                        or (state[5] or state[13] and state[21])))
        state[5] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[38] +
                (state[6] and state[14]
                        or (state[6] or state[14] and state[22])))
        state[6] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[39] +
                (state[7] and state[15]
                        or (state[7] or state[15] and state[23])))
        state[7] = circularLeftInt(tmp, p1) + tA[pp8k[isp + 4] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
        tA[0] = circularLeftInt(state[0], p1)
        tA[1] = circularLeftInt(state[1], p1)
        tA[2] = circularLeftInt(state[2], p1)
        tA[3] = circularLeftInt(state[3], p1)
        tA[4] = circularLeftInt(state[4], p1)
        tA[5] = circularLeftInt(state[5], p1)
        tA[6] = circularLeftInt(state[6], p1)
        tA[7] = circularLeftInt(state[7], p1)
        tmp = (state[24] + w[40] +
                (state[0] and state[8]
                        or (state[0] or state[8] and state[16])))
        state[0] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[41] +
                (state[1] and state[9]
                        or (state[1] or state[9] and state[17])))
        state[1] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[42] +
                (state[2] and state[10]
                        or (state[2] or state[10] and state[18])))
        state[2] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[43] +
                (state[3] and state[11]
                        or (state[3] or state[11] and state[19])))
        state[3] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[44] +
                (state[4] and state[12]
                        or (state[4] or state[12] and state[20])))
        state[4] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[45] +
                (state[5] and state[13]
                        or (state[5] or state[13] and state[21])))
        state[5] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[46] +
                (state[6] and state[14]
                        or (state[6] or state[14] and state[22])))
        state[6] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[47] +
                (state[7] and state[15]
                        or (state[7] or state[15] and state[23])))
        state[7] = circularLeftInt(tmp, p2) + tA[pp8k[isp + 5] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
        tA[0] = circularLeftInt(state[0], p2)
        tA[1] = circularLeftInt(state[1], p2)
        tA[2] = circularLeftInt(state[2], p2)
        tA[3] = circularLeftInt(state[3], p2)
        tA[4] = circularLeftInt(state[4], p2)
        tA[5] = circularLeftInt(state[5], p2)
        tA[6] = circularLeftInt(state[6], p2)
        tA[7] = circularLeftInt(state[7], p2)
        tmp = (state[24] + w[48] +
                (state[0] and state[8]
                        or (state[0] or state[8] and state[16])))
        state[0] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[49] +
                (state[1] and state[9]
                        or (state[1] or state[9] and state[17])))
        state[1] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[50] +
                (state[2] and state[10]
                        or (state[2] or state[10] and state[18])))
        state[2] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[51] +
                (state[3] and state[11]
                        or (state[3] or state[11] and state[19])))
        state[3] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[52] +
                (state[4] and state[12]
                        or (state[4] or state[12] and state[20])))
        state[4] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[53] +
                (state[5] and state[13]
                        or (state[5] or state[13] and state[21])))
        state[5] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[54] +
                (state[6] and state[14]
                        or (state[6] or state[14] and state[22])))
        state[6] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[55] +
                (state[7] and state[15]
                        or (state[7] or state[15] and state[23])))
        state[7] = circularLeftInt(tmp, p3) + tA[pp8k[isp + 6] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
        tA[0] = circularLeftInt(state[0], p3)
        tA[1] = circularLeftInt(state[1], p3)
        tA[2] = circularLeftInt(state[2], p3)
        tA[3] = circularLeftInt(state[3], p3)
        tA[4] = circularLeftInt(state[4], p3)
        tA[5] = circularLeftInt(state[5], p3)
        tA[6] = circularLeftInt(state[6], p3)
        tA[7] = circularLeftInt(state[7], p3)
        tmp = (state[24] + w[56] +
                (state[0] and state[8]
                        or (state[0] or state[8] and state[16])))
        state[0] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 0]
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA[0]
        tmp = (state[25] + w[57] +
                (state[1] and state[9]
                        or (state[1] or state[9] and state[17])))
        state[1] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 1]
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA[1]
        tmp = (state[26] + w[58] +
                (state[2] and state[10]
                        or (state[2] or state[10] and state[18])))
        state[2] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 2]
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA[2]
        tmp = (state[27] + w[59] +
                (state[3] and state[11]
                        or (state[3] or state[11] and state[19])))
        state[3] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 3]
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA[3]
        tmp = (state[28] + w[60] +
                (state[4] and state[12]
                        or (state[4] or state[12] and state[20])))
        state[4] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 4]
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA[4]
        tmp = (state[29] + w[61] +
                (state[5] and state[13]
                        or (state[5] or state[13] and state[21])))
        state[5] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 5]
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA[5]
        tmp = (state[30] + w[62] +
                (state[6] and state[14]
                        or (state[6] or state[14] and state[22])))
        state[6] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 6]
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA[6]
        tmp = (state[31] + w[63] +
                (state[7] and state[15]
                        or (state[7] or state[15] and state[23])))
        state[7] = circularLeftInt(tmp, p0) + tA[pp8k[isp + 7] xor 7]
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA[7]
    }

    @Suppress("ComplexMethod", "LongMethod")
    private fun compress(x: ByteArray, last: Boolean) {
        var tmp: Int
        fft64(x, 0 + 1 * 0, 1 shl 2, 0 + 0)
        fft64(x, 0 + 1 * 2, 1 shl 2, 0 + 64)
        var m = q[0]
        var n = q[0 + 64]
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
        fft64(x, 0 + 1 * 1, 1 shl 2, 0 + 128)
        fft64(x, 0 + 1 * 3, 1 shl 2, 0 + 192)
        m = q[0 + 128]
        n = q[0 + 128 + 64]
        q[0 + 128] = m + n
        q[0 + 128 + 64] = m - n
        run {
            var u = 0
            var v = 0
            while (u < 64) {
                var t: Int
                if (u != 0) {
                    m = q[0 + 128 + u + 0]
                    n = q[0 + 128 + u + 0 + 64]
                    t = ((n * alphaTab[v + 0 * 2] and 0xFFFF) +
                            (n * alphaTab[v + 0 * 2] shr 16))
                    q[0 + 128 + u + 0] = m + t
                    q[0 + 128 + u + 0 + 64] = m - t
                }
                m = q[0 + 128 + u + 1]
                n = q[0 + 128 + u + 1 + 64]
                t = ((n * alphaTab[v + 1 * 2] and 0xFFFF) +
                        (n * alphaTab[v + 1 * 2] shr 16))
                q[0 + 128 + u + 1] = m + t
                q[0 + 128 + u + 1 + 64] = m - t
                m = q[0 + 128 + u + 2]
                n = q[0 + 128 + u + 2 + 64]
                t = ((n * alphaTab[v + 2 * 2] and 0xFFFF) +
                        (n * alphaTab[v + 2 * 2] shr 16))
                q[0 + 128 + u + 2] = m + t
                q[0 + 128 + u + 2 + 64] = m - t
                m = q[0 + 128 + u + 3]
                n = q[0 + 128 + u + 3 + 64]
                t = ((n * alphaTab[v + 3 * 2] and 0xFFFF) +
                        (n * alphaTab[v + 3 * 2] shr 16))
                q[0 + 128 + u + 3] = m + t
                q[0 + 128 + u + 3 + 64] = m - t
                u += 4
                v += 4 * 2
            }
        }
        m = q[0]
        n = q[0 + 128]
        q[0] = m + n
        q[0 + 128] = m - n
        run {
            var u = 0
            var v = 0
            while (u < 128) {
                var t: Int
                if (u != 0) {
                    m = q[0 + u + 0]
                    n = q[0 + u + 0 + 128]
                    t = ((n * alphaTab[v + 0 * 1] and 0xFFFF) +
                            (n * alphaTab[v + 0 * 1] shr 16))
                    q[0 + u + 0] = m + t
                    q[0 + u + 0 + 128] = m - t
                }
                m = q[0 + u + 1]
                n = q[0 + u + 1 + 128]
                t = ((n * alphaTab[v + 1 * 1] and 0xFFFF) +
                        (n * alphaTab[v + 1 * 1] shr 16))
                q[0 + u + 1] = m + t
                q[0 + u + 1 + 128] = m - t
                m = q[0 + u + 2]
                n = q[0 + u + 2 + 128]
                t = ((n * alphaTab[v + 2 * 1] and 0xFFFF) +
                        (n * alphaTab[v + 2 * 1] shr 16))
                q[0 + u + 2] = m + t
                q[0 + u + 2 + 128] = m - t
                m = q[0 + u + 3]
                n = q[0 + u + 3 + 128]
                t = ((n * alphaTab[v + 3 * 1] and 0xFFFF) +
                        (n * alphaTab[v + 3 * 1] shr 16))
                q[0 + u + 3] = m + t
                q[0 + u + 3 + 128] = m - t
                u += 4
                v += 4 * 1
            }
        }
        if (last) {
            for (i in 0..255) {
                var tq = q[i] + yoffF[i]
                tq = (tq and 0xFFFF) + (tq shr 16)
                tq = (tq and 0xFF) - (tq shr 8)
                tq = (tq and 0xFF) - (tq shr 8)
                q[i] = if (tq <= 128) tq else tq - 257
            }
        } else {
            for (i in 0..255) {
                var tq = q[i] + yoffN[i]
                tq = (tq and 0xFFFF) + (tq shr 16)
                tq = (tq and 0xFF) - (tq shr 8)
                tq = (tq and 0xFF) - (tq shr 8)
                q[i] = if (tq <= 128) tq else tq - 257
            }
        }
        state.copyInto(tmpState, 0, 0, 32)
        var i = 0
        while (i < 32) {
            state[i + 0] = state[i + 0] xor decodeLEInt(x, 4 * (i + 0))
            state[i + 1] = state[i + 1] xor decodeLEInt(x, 4 * (i + 1))
            state[i + 2] = state[i + 2] xor decodeLEInt(x, 4 * (i + 2))
            state[i + 3] = state[i + 3] xor decodeLEInt(x, 4 * (i + 3))
            state[i + 4] = state[i + 4] xor decodeLEInt(x, 4 * (i + 4))
            state[i + 5] = state[i + 5] xor decodeLEInt(x, 4 * (i + 5))
            state[i + 6] = state[i + 6] xor decodeLEInt(x, 4 * (i + 6))
            state[i + 7] = state[i + 7] xor decodeLEInt(x, 4 * (i + 7))
            i += 8
        }
        run {
            var u = 0
            while (u < 64) {
                val v = wbp[(u shr 3) + 0]
                w[u + 0] = ((q[v + 2 * 0 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 0 + 1] * 185 shl 16))
                w[u + 1] = ((q[v + 2 * 1 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 1 + 1] * 185 shl 16))
                w[u + 2] = ((q[v + 2 * 2 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 2 + 1] * 185 shl 16))
                w[u + 3] = ((q[v + 2 * 3 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 3 + 1] * 185 shl 16))
                w[u + 4] = ((q[v + 2 * 4 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 4 + 1] * 185 shl 16))
                w[u + 5] = ((q[v + 2 * 5 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 5 + 1] * 185 shl 16))
                w[u + 6] = ((q[v + 2 * 6 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 6 + 1] * 185 shl 16))
                w[u + 7] = ((q[v + 2 * 7 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 7 + 1] * 185 shl 16))
                u += 8
            }
        }
        oneRound(0, 3, 23, 17, 27)
        run {
            var u = 0
            while (u < 64) {
                val v = wbp[(u shr 3) + 8]
                w[u + 0] = ((q[v + 2 * 0 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 0 + 1] * 185 shl 16))
                w[u + 1] = ((q[v + 2 * 1 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 1 + 1] * 185 shl 16))
                w[u + 2] = ((q[v + 2 * 2 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 2 + 1] * 185 shl 16))
                w[u + 3] = ((q[v + 2 * 3 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 3 + 1] * 185 shl 16))
                w[u + 4] = ((q[v + 2 * 4 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 4 + 1] * 185 shl 16))
                w[u + 5] = ((q[v + 2 * 5 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 5 + 1] * 185 shl 16))
                w[u + 6] = ((q[v + 2 * 6 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 6 + 1] * 185 shl 16))
                w[u + 7] = ((q[v + 2 * 7 + 0] * 185 and 0xFFFF) +
                        (q[v + 2 * 7 + 1] * 185 shl 16))
                u += 8
            }
        }
        oneRound(1, 28, 19, 22, 7)
        run {
            var u = 0
            while (u < 64) {
                val v = wbp[(u shr 3) + 16]
                w[u + 0] = ((q[v + 2 * 0 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 0 + -128] * 233 shl 16))
                w[u + 1] = ((q[v + 2 * 1 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 1 + -128] * 233 shl 16))
                w[u + 2] = ((q[v + 2 * 2 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 2 + -128] * 233 shl 16))
                w[u + 3] = ((q[v + 2 * 3 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 3 + -128] * 233 shl 16))
                w[u + 4] = ((q[v + 2 * 4 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 4 + -128] * 233 shl 16))
                w[u + 5] = ((q[v + 2 * 5 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 5 + -128] * 233 shl 16))
                w[u + 6] = ((q[v + 2 * 6 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 6 + -128] * 233 shl 16))
                w[u + 7] = ((q[v + 2 * 7 + -256] * 233 and 0xFFFF) +
                        (q[v + 2 * 7 + -128] * 233 shl 16))
                u += 8
            }
        }
        oneRound(2, 29, 9, 15, 5)
        var u = 0
        while (u < 64) {
            val v = wbp[(u shr 3) + 24]
            w[u + 0] = ((q[v + 2 * 0 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 0 + -255] * 233 shl 16))
            w[u + 1] = ((q[v + 2 * 1 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 1 + -255] * 233 shl 16))
            w[u + 2] = ((q[v + 2 * 2 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 2 + -255] * 233 shl 16))
            w[u + 3] = ((q[v + 2 * 3 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 3 + -255] * 233 shl 16))
            w[u + 4] = ((q[v + 2 * 4 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 4 + -255] * 233 shl 16))
            w[u + 5] = ((q[v + 2 * 5 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 5 + -255] * 233 shl 16))
            w[u + 6] = ((q[v + 2 * 6 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 6 + -255] * 233 shl 16))
            w[u + 7] = ((q[v + 2 * 7 + -383] * 233 and 0xFFFF) +
                    (q[v + 2 * 7 + -255] * 233 shl 16))
            u += 8
        }
        oneRound(3, 4, 13, 10, 25)
        run {
            val tA0 = circularLeftInt(state[0], 4)
            val tA1 = circularLeftInt(state[1], 4)
            val tA2 = circularLeftInt(state[2], 4)
            val tA3 = circularLeftInt(state[3], 4)
            val tA4 = circularLeftInt(state[4], 4)
            val tA5 = circularLeftInt(state[5], 4)
            val tA6 = circularLeftInt(state[6], 4)
            val tA7 = circularLeftInt(state[7], 4)
            tmp = state[24] + tmpState[0] + ((state[8]
                    xor state[16]) and state[0] xor state[16])
            state[0] = circularLeftInt(tmp, 13) + tA5
            state[24] = state[16]
            state[16] = state[8]
            state[8] = tA0
            tmp = state[25] + tmpState[1] + ((state[9]
                    xor state[17]) and state[1] xor state[17])
            state[1] = circularLeftInt(tmp, 13) + tA4
            state[25] = state[17]
            state[17] = state[9]
            state[9] = tA1
            tmp = state[26] + tmpState[2] + ((state[10]
                    xor state[18]) and state[2] xor state[18])
            state[2] = circularLeftInt(tmp, 13) + tA7
            state[26] = state[18]
            state[18] = state[10]
            state[10] = tA2
            tmp = state[27] + tmpState[3] + ((state[11]
                    xor state[19]) and state[3] xor state[19])
            state[3] = circularLeftInt(tmp, 13) + tA6
            state[27] = state[19]
            state[19] = state[11]
            state[11] = tA3
            tmp = state[28] + tmpState[4] + ((state[12]
                    xor state[20]) and state[4] xor state[20])
            state[4] = circularLeftInt(tmp, 13) + tA1
            state[28] = state[20]
            state[20] = state[12]
            state[12] = tA4
            tmp = state[29] + tmpState[5] + ((state[13]
                    xor state[21]) and state[5] xor state[21])
            state[5] = circularLeftInt(tmp, 13) + tA0
            state[29] = state[21]
            state[21] = state[13]
            state[13] = tA5
            tmp = state[30] + tmpState[6] + ((state[14]
                    xor state[22]) and state[6] xor state[22])
            state[6] = circularLeftInt(tmp, 13) + tA3
            state[30] = state[22]
            state[22] = state[14]
            state[14] = tA6
            tmp = state[31] + tmpState[7] + ((state[15]
                    xor state[23]) and state[7] xor state[23])
            state[7] = circularLeftInt(tmp, 13) + tA2
            state[31] = state[23]
            state[23] = state[15]
            state[15] = tA7
        }
        run {
            val tA0 = circularLeftInt(state[0], 13)
            val tA1 = circularLeftInt(state[1], 13)
            val tA2 = circularLeftInt(state[2], 13)
            val tA3 = circularLeftInt(state[3], 13)
            val tA4 = circularLeftInt(state[4], 13)
            val tA5 = circularLeftInt(state[5], 13)
            val tA6 = circularLeftInt(state[6], 13)
            val tA7 = circularLeftInt(state[7], 13)
            tmp = state[24] + tmpState[8] + ((state[8]
                    xor state[16]) and state[0] xor state[16])
            state[0] = circularLeftInt(tmp, 10) + tA7
            state[24] = state[16]
            state[16] = state[8]
            state[8] = tA0
            tmp = state[25] + tmpState[9] + ((state[9]
                    xor state[17]) and state[1] xor state[17])
            state[1] = circularLeftInt(tmp, 10) + tA6
            state[25] = state[17]
            state[17] = state[9]
            state[9] = tA1
            tmp = state[26] + tmpState[10] + ((state[10]
                    xor state[18]) and state[2] xor state[18])
            state[2] = circularLeftInt(tmp, 10) + tA5
            state[26] = state[18]
            state[18] = state[10]
            state[10] = tA2
            tmp = state[27] + tmpState[11] + ((state[11]
                    xor state[19]) and state[3] xor state[19])
            state[3] = circularLeftInt(tmp, 10) + tA4
            state[27] = state[19]
            state[19] = state[11]
            state[11] = tA3
            tmp = state[28] + tmpState[12] + ((state[12]
                    xor state[20]) and state[4] xor state[20])
            state[4] = circularLeftInt(tmp, 10) + tA3
            state[28] = state[20]
            state[20] = state[12]
            state[12] = tA4
            tmp = state[29] + tmpState[13] + ((state[13]
                    xor state[21]) and state[5] xor state[21])
            state[5] = circularLeftInt(tmp, 10) + tA2
            state[29] = state[21]
            state[21] = state[13]
            state[13] = tA5
            tmp = state[30] + tmpState[14] + ((state[14]
                    xor state[22]) and state[6] xor state[22])
            state[6] = circularLeftInt(tmp, 10) + tA1
            state[30] = state[22]
            state[22] = state[14]
            state[14] = tA6
            tmp = state[31] + tmpState[15] + ((state[15]
                    xor state[23]) and state[7] xor state[23])
            state[7] = circularLeftInt(tmp, 10) + tA0
            state[31] = state[23]
            state[23] = state[15]
            state[15] = tA7
        }
        run {
            val tA0 = circularLeftInt(state[0], 10)
            val tA1 = circularLeftInt(state[1], 10)
            val tA2 = circularLeftInt(state[2], 10)
            val tA3 = circularLeftInt(state[3], 10)
            val tA4 = circularLeftInt(state[4], 10)
            val tA5 = circularLeftInt(state[5], 10)
            val tA6 = circularLeftInt(state[6], 10)
            val tA7 = circularLeftInt(state[7], 10)
            tmp = state[24] + tmpState[16] + ((state[8]
                    xor state[16]) and state[0] xor state[16])
            state[0] = circularLeftInt(tmp, 25) + tA4
            state[24] = state[16]
            state[16] = state[8]
            state[8] = tA0
            tmp = state[25] + tmpState[17] + ((state[9]
                    xor state[17]) and state[1] xor state[17])
            state[1] = circularLeftInt(tmp, 25) + tA5
            state[25] = state[17]
            state[17] = state[9]
            state[9] = tA1
            tmp = state[26] + tmpState[18] + ((state[10]
                    xor state[18]) and state[2] xor state[18])
            state[2] = circularLeftInt(tmp, 25) + tA6
            state[26] = state[18]
            state[18] = state[10]
            state[10] = tA2
            tmp = state[27] + tmpState[19] + ((state[11]
                    xor state[19]) and state[3] xor state[19])
            state[3] = circularLeftInt(tmp, 25) + tA7
            state[27] = state[19]
            state[19] = state[11]
            state[11] = tA3
            tmp = state[28] + tmpState[20] + ((state[12]
                    xor state[20]) and state[4] xor state[20])
            state[4] = circularLeftInt(tmp, 25) + tA0
            state[28] = state[20]
            state[20] = state[12]
            state[12] = tA4
            tmp = state[29] + tmpState[21] + ((state[13]
                    xor state[21]) and state[5] xor state[21])
            state[5] = circularLeftInt(tmp, 25) + tA1
            state[29] = state[21]
            state[21] = state[13]
            state[13] = tA5
            tmp = state[30] + tmpState[22] + ((state[14]
                    xor state[22]) and state[6] xor state[22])
            state[6] = circularLeftInt(tmp, 25) + tA2
            state[30] = state[22]
            state[22] = state[14]
            state[14] = tA6
            tmp = state[31] + tmpState[23] + ((state[15]
                    xor state[23]) and state[7] xor state[23])
            state[7] = circularLeftInt(tmp, 25) + tA3
            state[31] = state[23]
            state[23] = state[15]
            state[15] = tA7
        }
        run {
            val tA0 = circularLeftInt(state[0], 25)
            val tA1 = circularLeftInt(state[1], 25)
            val tA2 = circularLeftInt(state[2], 25)
            val tA3 = circularLeftInt(state[3], 25)
            val tA4 = circularLeftInt(state[4], 25)
            val tA5 = circularLeftInt(state[5], 25)
            val tA6 = circularLeftInt(state[6], 25)
            val tA7 = circularLeftInt(state[7], 25)
            tmp = state[24] + tmpState[24] + ((state[8]
                    xor state[16]) and state[0] xor state[16])
            state[0] = circularLeftInt(tmp, 4) + tA1
            state[24] = state[16]
            state[16] = state[8]
            state[8] = tA0
            tmp = state[25] + tmpState[25] + ((state[9]
                    xor state[17]) and state[1] xor state[17])
            state[1] = circularLeftInt(tmp, 4) + tA0
            state[25] = state[17]
            state[17] = state[9]
            state[9] = tA1
            tmp = state[26] + tmpState[26] + ((state[10]
                    xor state[18]) and state[2] xor state[18])
            state[2] = circularLeftInt(tmp, 4) + tA3
            state[26] = state[18]
            state[18] = state[10]
            state[10] = tA2
            tmp = state[27] + tmpState[27] + ((state[11]
                    xor state[19]) and state[3] xor state[19])
            state[3] = circularLeftInt(tmp, 4) + tA2
            state[27] = state[19]
            state[19] = state[11]
            state[11] = tA3
            tmp = state[28] + tmpState[28] + ((state[12]
                    xor state[20]) and state[4] xor state[20])
            state[4] = circularLeftInt(tmp, 4) + tA5
            state[28] = state[20]
            state[20] = state[12]
            state[12] = tA4
            tmp = state[29] + tmpState[29] + ((state[13]
                    xor state[21]) and state[5] xor state[21])
            state[5] = circularLeftInt(tmp, 4) + tA4
            state[29] = state[21]
            state[21] = state[13]
            state[13] = tA5
            tmp = state[30] + tmpState[30] + ((state[14]
                    xor state[22]) and state[6] xor state[22])
            state[6] = circularLeftInt(tmp, 4) + tA7
            state[30] = state[22]
            state[22] = state[14]
            state[14] = tA6
            tmp = state[31] + tmpState[31] + ((state[15]
                    xor state[23]) and state[7] xor state[23])
            state[7] = circularLeftInt(tmp, 4) + tA6
            state[31] = state[23]
            state[23] = state[15]
            state[15] = tA7
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
            1, 163, 98, 40, 95, 65, 58, 202, 30, 7, 113, 172,
            23, 151, 198, 149, 129, 210, 49, 20, 176, 161, 29, 101,
            15, 132, 185, 86, 140, 204, 99, 203, 193, 105, 153, 10,
            88, 209, 143, 179, 136, 66, 221, 43, 70, 102, 178, 230,
            225, 181, 205, 5, 44, 233, 200, 218, 68, 33, 239, 150,
            35, 51, 89, 115, 241, 219, 231, 131, 22, 245, 100, 109,
            34, 145, 248, 75, 146, 154, 173, 186, 249, 238, 244, 194,
            11, 251, 50, 183, 17, 201, 124, 166, 73, 77, 215, 93,
            253, 119, 122, 97, 134, 254, 25, 220, 137, 229, 62, 83,
            165, 167, 236, 175, 255, 188, 61, 177, 67, 127, 141, 110,
            197, 243, 31, 170, 211, 212, 118, 216, 256, 94, 159, 217,
            162, 192, 199, 55, 227, 250, 144, 85, 234, 106, 59, 108,
            128, 47, 208, 237, 81, 96, 228, 156, 242, 125, 72, 171,
            117, 53, 158, 54, 64, 152, 104, 247, 169, 48, 114, 78,
            121, 191, 36, 214, 187, 155, 79, 27, 32, 76, 52, 252,
            213, 24, 57, 39, 189, 224, 18, 107, 222, 206, 168, 142,
            16, 38, 26, 126, 235, 12, 157, 148, 223, 112, 9, 182,
            111, 103, 84, 71, 8, 19, 13, 63, 246, 6, 207, 74,
            240, 56, 133, 91, 184, 180, 42, 164, 4, 138, 135, 160,
            123, 3, 232, 37, 120, 28, 195, 174, 92, 90, 21, 82,
            2, 69, 196, 80, 190, 130, 116, 147, 60, 14, 226, 87,
            46, 45, 139, 41
        )
        private val yoffF = intArrayOf(
            2, 203, 156, 47, 118, 214, 107, 106, 45, 93, 212, 20,
            111, 73, 162, 251, 97, 215, 249, 53, 211, 19, 3, 89,
            49, 207, 101, 67, 151, 130, 223, 23, 189, 202, 178, 239,
            253, 127, 204, 49, 76, 236, 82, 137, 232, 157, 65, 79,
            96, 161, 176, 130, 161, 30, 47, 9, 189, 247, 61, 226,
            248, 90, 107, 64, 0, 88, 131, 243, 133, 59, 113, 115,
            17, 236, 33, 213, 12, 191, 111, 19, 251, 61, 103, 208,
            57, 35, 148, 248, 47, 116, 65, 119, 249, 178, 143, 40,
            189, 129, 8, 163, 204, 227, 230, 196, 205, 122, 151, 45,
            187, 19, 227, 72, 247, 125, 111, 121, 140, 220, 6, 107,
            77, 69, 10, 101, 21, 65, 149, 171, 255, 54, 101, 210,
            139, 43, 150, 151, 212, 164, 45, 237, 146, 184, 95, 6,
            160, 42, 8, 204, 46, 238, 254, 168, 208, 50, 156, 190,
            106, 127, 34, 234, 68, 55, 79, 18, 4, 130, 53, 208,
            181, 21, 175, 120, 25, 100, 192, 178, 161, 96, 81, 127,
            96, 227, 210, 248, 68, 10, 196, 31, 9, 167, 150, 193,
            0, 169, 126, 14, 124, 198, 144, 142, 240, 21, 224, 44,
            245, 66, 146, 238, 6, 196, 154, 49, 200, 222, 109, 9,
            210, 141, 192, 138, 8, 79, 114, 217, 68, 128, 249, 94,
            53, 30, 27, 61, 52, 135, 106, 212, 70, 238, 30, 185,
            10, 132, 146, 136, 117, 37, 251, 150, 180, 188, 247, 156,
            236, 192, 108, 86
        )
        private val pp8k = intArrayOf(
            1, 6, 2, 3, 5, 7, 4, 1, 6, 2, 3
        )
        private val wbp = intArrayOf(
            4 shl 4, 6 shl 4, 0 shl 4, 2 shl 4,
            7 shl 4, 5 shl 4, 3 shl 4, 1 shl 4,
            15 shl 4, 11 shl 4, 12 shl 4, 8 shl 4,
            9 shl 4, 13 shl 4, 10 shl 4, 14 shl 4,
            17 shl 4, 18 shl 4, 23 shl 4, 20 shl 4,
            22 shl 4, 21 shl 4, 16 shl 4, 19 shl 4,
            30 shl 4, 24 shl 4, 25 shl 4, 31 shl 4,
            27 shl 4, 29 shl 4, 28 shl 4, 26 shl 4
        )
    }
}
