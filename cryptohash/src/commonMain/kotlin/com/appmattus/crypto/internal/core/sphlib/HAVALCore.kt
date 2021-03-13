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
 * This class implements the HAVAL digest algorithm, which accepts 15
 * variants based on the number of passes and digest output.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 *
 * @param outputLength   output length (in bits)
 * @param passes         number of passes (3, 4 or 5)
 */
@Suppress("TooManyFunctions", "MagicNumber", "LargeClass")
internal class HAVALCore(private val outputLength: Int, private val passes: Int) : DigestEngine<HAVALCore>() {

    init {
        require(outputLength in listOf(128, 160, 192, 224, 256))
        require(passes in listOf(3, 4, 5))
    }

    /**
     * Output length, in 32-bit words (4, 5, 6, 7, or 8).
     */
    private val olen: Int = outputLength shr 5

    /**
     * Padding buffer.
     */
    private lateinit var padBuf: ByteArray

    /**
     * State variables.
     */
    private var s0 = 0
    private var s1 = 0
    private var s2 = 0
    private var s3 = 0
    private var s4 = 0
    private var s5 = 0
    private var s6 = 0
    private var s7 = 0

    /**
     * Pre-allocated array for input words.
     */
    private lateinit var inw: IntArray

    override fun copyState(dest: HAVALCore): HAVALCore {
        dest.s0 = s0
        dest.s1 = s1
        dest.s2 = s2
        dest.s3 = s3
        dest.s4 = s4
        dest.s5 = s5
        dest.s6 = s6
        dest.s7 = s7
        return super.copyState(dest)
    }

    override val blockLength: Int
        get() = 128

    override fun engineReset() {
        s0 = 0x243F6A88
        s1 = -0x7a5cf72d
        s2 = 0x13198A2E
        s3 = 0x03707344
        s4 = -0x5bf6c7de
        s5 = 0x299F31D0
        s6 = 0x082EFA98
        s7 = -0x13b19377
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val dataLen = flush()
        val currentLength = (blockCount shl 7) + dataLen.toLong() shl 3
        padBuf[0] = (0x01 or (passes shl 3)).toByte()
        padBuf[1] = (olen shl 3).toByte()
        encodeLEInt(currentLength.toInt(), padBuf, 2)
        encodeLEInt((currentLength ushr 32).toInt(), padBuf, 6)
        val endLen = dataLen + 138 and 127.inv()
        update(0x01.toByte())
        for (i in dataLen + 1 until endLen - 10) update(0.toByte())
        update(padBuf)

        writeOutput(output, outputOffset)
    }

    override fun doInit() {
        padBuf = ByteArray(10)
        inw = IntArray(32)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        for (i in 0..31) inw[i] = decodeLEInt(data, 4 * i)
        val save0 = s0
        val save1 = s1
        val save2 = s2
        val save3 = s3
        val save4 = s4
        val save5 = s5
        val save6 = s6
        val save7 = s7
        when (passes) {
            3 -> {
                pass31(inw)
                pass32(inw)
                pass33(inw)
            }
            4 -> {
                pass41(inw)
                pass42(inw)
                pass43(inw)
                pass44(inw)
            }
            5 -> {
                pass51(inw)
                pass52(inw)
                pass53(inw)
                pass54(inw)
                pass55(inw)
            }
        }
        s0 += save0
        s1 += save1
        s2 += save2
        s3 += save3
        s4 += save4
        s5 += save5
        s6 += save6
        s7 += save7
    }

    private fun pass31(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f1(x1, x0, x3, x5, x6, x2, x4), 25) +
                    circularLeftInt(x7, 21) + inw[i + 0])
            x6 = (circularLeftInt(f1(x0, x7, x2, x4, x5, x1, x3), 25) +
                    circularLeftInt(x6, 21) + inw[i + 1])
            x5 = (circularLeftInt(f1(x7, x6, x1, x3, x4, x0, x2), 25) +
                    circularLeftInt(x5, 21) + inw[i + 2])
            x4 = (circularLeftInt(f1(x6, x5, x0, x2, x3, x7, x1), 25) +
                    circularLeftInt(x4, 21) + inw[i + 3])
            x3 = (circularLeftInt(f1(x5, x4, x7, x1, x2, x6, x0), 25) +
                    circularLeftInt(x3, 21) + inw[i + 4])
            x2 = (circularLeftInt(f1(x4, x3, x6, x0, x1, x5, x7), 25) +
                    circularLeftInt(x2, 21) + inw[i + 5])
            x1 = (circularLeftInt(f1(x3, x2, x5, x7, x0, x4, x6), 25) +
                    circularLeftInt(x1, 21) + inw[i + 6])
            x0 = (circularLeftInt(f1(x2, x1, x4, x6, x7, x3, x5), 25) +
                    circularLeftInt(x0, 21) + inw[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass32(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f2(x4, x2, x1, x0, x5, x3, x6), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp2[i + 0]] + K2[i + 0])
            x6 = (circularLeftInt(f2(x3, x1, x0, x7, x4, x2, x5), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp2[i + 1]] + K2[i + 1])
            x5 = (circularLeftInt(f2(x2, x0, x7, x6, x3, x1, x4), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp2[i + 2]] + K2[i + 2])
            x4 = (circularLeftInt(f2(x1, x7, x6, x5, x2, x0, x3), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp2[i + 3]] + K2[i + 3])
            x3 = (circularLeftInt(f2(x0, x6, x5, x4, x1, x7, x2), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp2[i + 4]] + K2[i + 4])
            x2 = (circularLeftInt(f2(x7, x5, x4, x3, x0, x6, x1), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp2[i + 5]] + K2[i + 5])
            x1 = (circularLeftInt(f2(x6, x4, x3, x2, x7, x5, x0), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp2[i + 6]] + K2[i + 6])
            x0 = (circularLeftInt(f2(x5, x3, x2, x1, x6, x4, x7), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp2[i + 7]] + K2[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass33(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f3(x6, x1, x2, x3, x4, x5, x0), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp3[i + 0]] + K3[i + 0])
            x6 = (circularLeftInt(f3(x5, x0, x1, x2, x3, x4, x7), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp3[i + 1]] + K3[i + 1])
            x5 = (circularLeftInt(f3(x4, x7, x0, x1, x2, x3, x6), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp3[i + 2]] + K3[i + 2])
            x4 = (circularLeftInt(f3(x3, x6, x7, x0, x1, x2, x5), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp3[i + 3]] + K3[i + 3])
            x3 = (circularLeftInt(f3(x2, x5, x6, x7, x0, x1, x4), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp3[i + 4]] + K3[i + 4])
            x2 = (circularLeftInt(f3(x1, x4, x5, x6, x7, x0, x3), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp3[i + 5]] + K3[i + 5])
            x1 = (circularLeftInt(f3(x0, x3, x4, x5, x6, x7, x2), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp3[i + 6]] + K3[i + 6])
            x0 = (circularLeftInt(f3(x7, x2, x3, x4, x5, x6, x1), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp3[i + 7]] + K3[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass41(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f1(x2, x6, x1, x4, x5, x3, x0), 25) +
                    circularLeftInt(x7, 21) + inw[i + 0])
            x6 = (circularLeftInt(f1(x1, x5, x0, x3, x4, x2, x7), 25) +
                    circularLeftInt(x6, 21) + inw[i + 1])
            x5 = (circularLeftInt(f1(x0, x4, x7, x2, x3, x1, x6), 25) +
                    circularLeftInt(x5, 21) + inw[i + 2])
            x4 = (circularLeftInt(f1(x7, x3, x6, x1, x2, x0, x5), 25) +
                    circularLeftInt(x4, 21) + inw[i + 3])
            x3 = (circularLeftInt(f1(x6, x2, x5, x0, x1, x7, x4), 25) +
                    circularLeftInt(x3, 21) + inw[i + 4])
            x2 = (circularLeftInt(f1(x5, x1, x4, x7, x0, x6, x3), 25) +
                    circularLeftInt(x2, 21) + inw[i + 5])
            x1 = (circularLeftInt(f1(x4, x0, x3, x6, x7, x5, x2), 25) +
                    circularLeftInt(x1, 21) + inw[i + 6])
            x0 = (circularLeftInt(f1(x3, x7, x2, x5, x6, x4, x1), 25) +
                    circularLeftInt(x0, 21) + inw[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass42(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f2(x3, x5, x2, x0, x1, x6, x4), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp2[i + 0]] + K2[i + 0])
            x6 = (circularLeftInt(f2(x2, x4, x1, x7, x0, x5, x3), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp2[i + 1]] + K2[i + 1])
            x5 = (circularLeftInt(f2(x1, x3, x0, x6, x7, x4, x2), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp2[i + 2]] + K2[i + 2])
            x4 = (circularLeftInt(f2(x0, x2, x7, x5, x6, x3, x1), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp2[i + 3]] + K2[i + 3])
            x3 = (circularLeftInt(f2(x7, x1, x6, x4, x5, x2, x0), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp2[i + 4]] + K2[i + 4])
            x2 = (circularLeftInt(f2(x6, x0, x5, x3, x4, x1, x7), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp2[i + 5]] + K2[i + 5])
            x1 = (circularLeftInt(f2(x5, x7, x4, x2, x3, x0, x6), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp2[i + 6]] + K2[i + 6])
            x0 = (circularLeftInt(f2(x4, x6, x3, x1, x2, x7, x5), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp2[i + 7]] + K2[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass43(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f3(x1, x4, x3, x6, x0, x2, x5), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp3[i + 0]] + K3[i + 0])
            x6 = (circularLeftInt(f3(x0, x3, x2, x5, x7, x1, x4), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp3[i + 1]] + K3[i + 1])
            x5 = (circularLeftInt(f3(x7, x2, x1, x4, x6, x0, x3), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp3[i + 2]] + K3[i + 2])
            x4 = (circularLeftInt(f3(x6, x1, x0, x3, x5, x7, x2), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp3[i + 3]] + K3[i + 3])
            x3 = (circularLeftInt(f3(x5, x0, x7, x2, x4, x6, x1), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp3[i + 4]] + K3[i + 4])
            x2 = (circularLeftInt(f3(x4, x7, x6, x1, x3, x5, x0), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp3[i + 5]] + K3[i + 5])
            x1 = (circularLeftInt(f3(x3, x6, x5, x0, x2, x4, x7), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp3[i + 6]] + K3[i + 6])
            x0 = (circularLeftInt(f3(x2, x5, x4, x7, x1, x3, x6), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp3[i + 7]] + K3[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass44(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f4(x6, x4, x0, x5, x2, x1, x3), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp4[i + 0]] + K4[i + 0])
            x6 = (circularLeftInt(f4(x5, x3, x7, x4, x1, x0, x2), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp4[i + 1]] + K4[i + 1])
            x5 = (circularLeftInt(f4(x4, x2, x6, x3, x0, x7, x1), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp4[i + 2]] + K4[i + 2])
            x4 = (circularLeftInt(f4(x3, x1, x5, x2, x7, x6, x0), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp4[i + 3]] + K4[i + 3])
            x3 = (circularLeftInt(f4(x2, x0, x4, x1, x6, x5, x7), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp4[i + 4]] + K4[i + 4])
            x2 = (circularLeftInt(f4(x1, x7, x3, x0, x5, x4, x6), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp4[i + 5]] + K4[i + 5])
            x1 = (circularLeftInt(f4(x0, x6, x2, x7, x4, x3, x5), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp4[i + 6]] + K4[i + 6])
            x0 = (circularLeftInt(f4(x7, x5, x1, x6, x3, x2, x4), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp4[i + 7]] + K4[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass51(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f1(x3, x4, x1, x0, x5, x2, x6), 25) +
                    circularLeftInt(x7, 21) + inw[i + 0])
            x6 = (circularLeftInt(f1(x2, x3, x0, x7, x4, x1, x5), 25) +
                    circularLeftInt(x6, 21) + inw[i + 1])
            x5 = (circularLeftInt(f1(x1, x2, x7, x6, x3, x0, x4), 25) +
                    circularLeftInt(x5, 21) + inw[i + 2])
            x4 = (circularLeftInt(f1(x0, x1, x6, x5, x2, x7, x3), 25) +
                    circularLeftInt(x4, 21) + inw[i + 3])
            x3 = (circularLeftInt(f1(x7, x0, x5, x4, x1, x6, x2), 25) +
                    circularLeftInt(x3, 21) + inw[i + 4])
            x2 = (circularLeftInt(f1(x6, x7, x4, x3, x0, x5, x1), 25) +
                    circularLeftInt(x2, 21) + inw[i + 5])
            x1 = (circularLeftInt(f1(x5, x6, x3, x2, x7, x4, x0), 25) +
                    circularLeftInt(x1, 21) + inw[i + 6])
            x0 = (circularLeftInt(f1(x4, x5, x2, x1, x6, x3, x7), 25) +
                    circularLeftInt(x0, 21) + inw[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass52(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f2(x6, x2, x1, x0, x3, x4, x5), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp2[i + 0]] + K2[i + 0])
            x6 = (circularLeftInt(f2(x5, x1, x0, x7, x2, x3, x4), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp2[i + 1]] + K2[i + 1])
            x5 = (circularLeftInt(f2(x4, x0, x7, x6, x1, x2, x3), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp2[i + 2]] + K2[i + 2])
            x4 = (circularLeftInt(f2(x3, x7, x6, x5, x0, x1, x2), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp2[i + 3]] + K2[i + 3])
            x3 = (circularLeftInt(f2(x2, x6, x5, x4, x7, x0, x1), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp2[i + 4]] + K2[i + 4])
            x2 = (circularLeftInt(f2(x1, x5, x4, x3, x6, x7, x0), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp2[i + 5]] + K2[i + 5])
            x1 = (circularLeftInt(f2(x0, x4, x3, x2, x5, x6, x7), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp2[i + 6]] + K2[i + 6])
            x0 = (circularLeftInt(f2(x7, x3, x2, x1, x4, x5, x6), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp2[i + 7]] + K2[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass53(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f3(x2, x6, x0, x4, x3, x1, x5), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp3[i + 0]] + K3[i + 0])
            x6 = (circularLeftInt(f3(x1, x5, x7, x3, x2, x0, x4), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp3[i + 1]] + K3[i + 1])
            x5 = (circularLeftInt(f3(x0, x4, x6, x2, x1, x7, x3), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp3[i + 2]] + K3[i + 2])
            x4 = (circularLeftInt(f3(x7, x3, x5, x1, x0, x6, x2), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp3[i + 3]] + K3[i + 3])
            x3 = (circularLeftInt(f3(x6, x2, x4, x0, x7, x5, x1), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp3[i + 4]] + K3[i + 4])
            x2 = (circularLeftInt(f3(x5, x1, x3, x7, x6, x4, x0), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp3[i + 5]] + K3[i + 5])
            x1 = (circularLeftInt(f3(x4, x0, x2, x6, x5, x3, x7), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp3[i + 6]] + K3[i + 6])
            x0 = (circularLeftInt(f3(x3, x7, x1, x5, x4, x2, x6), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp3[i + 7]] + K3[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass54(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f4(x1, x5, x3, x2, x0, x4, x6), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp4[i + 0]] + K4[i + 0])
            x6 = (circularLeftInt(f4(x0, x4, x2, x1, x7, x3, x5), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp4[i + 1]] + K4[i + 1])
            x5 = (circularLeftInt(f4(x7, x3, x1, x0, x6, x2, x4), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp4[i + 2]] + K4[i + 2])
            x4 = (circularLeftInt(f4(x6, x2, x0, x7, x5, x1, x3), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp4[i + 3]] + K4[i + 3])
            x3 = (circularLeftInt(f4(x5, x1, x7, x6, x4, x0, x2), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp4[i + 4]] + K4[i + 4])
            x2 = (circularLeftInt(f4(x4, x0, x6, x5, x3, x7, x1), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp4[i + 5]] + K4[i + 5])
            x1 = (circularLeftInt(f4(x3, x7, x5, x4, x2, x6, x0), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp4[i + 6]] + K4[i + 6])
            x0 = (circularLeftInt(f4(x2, x6, x4, x3, x1, x5, x7), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp4[i + 7]] + K4[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun pass55(inw: IntArray) {
        var x0 = s0
        var x1 = s1
        var x2 = s2
        var x3 = s3
        var x4 = s4
        var x5 = s5
        var x6 = s6
        var x7 = s7
        var i = 0
        while (i < 32) {
            x7 = (circularLeftInt(f5(x2, x5, x0, x6, x4, x3, x1), 25) +
                    circularLeftInt(x7, 21) +
                    inw[wp5[i + 0]] + K5[i + 0])
            x6 = (circularLeftInt(f5(x1, x4, x7, x5, x3, x2, x0), 25) +
                    circularLeftInt(x6, 21) +
                    inw[wp5[i + 1]] + K5[i + 1])
            x5 = (circularLeftInt(f5(x0, x3, x6, x4, x2, x1, x7), 25) +
                    circularLeftInt(x5, 21) +
                    inw[wp5[i + 2]] + K5[i + 2])
            x4 = (circularLeftInt(f5(x7, x2, x5, x3, x1, x0, x6), 25) +
                    circularLeftInt(x4, 21) +
                    inw[wp5[i + 3]] + K5[i + 3])
            x3 = (circularLeftInt(f5(x6, x1, x4, x2, x0, x7, x5), 25) +
                    circularLeftInt(x3, 21) +
                    inw[wp5[i + 4]] + K5[i + 4])
            x2 = (circularLeftInt(f5(x5, x0, x3, x1, x7, x6, x4), 25) +
                    circularLeftInt(x2, 21) +
                    inw[wp5[i + 5]] + K5[i + 5])
            x1 = (circularLeftInt(f5(x4, x7, x2, x0, x6, x5, x3), 25) +
                    circularLeftInt(x1, 21) +
                    inw[wp5[i + 6]] + K5[i + 6])
            x0 = (circularLeftInt(f5(x3, x6, x1, x7, x5, x4, x2), 25) +
                    circularLeftInt(x0, 21) +
                    inw[wp5[i + 7]] + K5[i + 7])
            i += 8
        }
        s0 = x0
        s1 = x1
        s2 = x2
        s3 = x3
        s4 = x4
        s5 = x5
        s6 = x6
        s7 = x7
    }

    private fun write128(out: ByteArray, off: Int) {
        encodeLEInt(s0 + mix128(s7, s4, s5, s6, 24), out, off)
        encodeLEInt(s1 + mix128(s6, s7, s4, s5, 16), out, off + 4)
        encodeLEInt(s2 + mix128(s5, s6, s7, s4, 8), out, off + 8)
        encodeLEInt(s3 + mix128(s4, s5, s6, s7, 0), out, off + 12)
    }

    private fun write160(out: ByteArray, off: Int) {
        encodeLEInt(s0 + mix160_0(s5, s6, s7), out, off)
        encodeLEInt(s1 + mix160_1(s5, s6, s7), out, off + 4)
        encodeLEInt(s2 + mix160_2(s5, s6, s7), out, off + 8)
        encodeLEInt(s3 + mix160_3(s5, s6, s7), out, off + 12)
        encodeLEInt(s4 + mix160_4(s5, s6, s7), out, off + 16)
    }

    private fun write192(out: ByteArray, off: Int) {
        encodeLEInt(s0 + mix192_0(s6, s7), out, off)
        encodeLEInt(s1 + mix192_1(s6, s7), out, off + 4)
        encodeLEInt(s2 + mix192_2(s6, s7), out, off + 8)
        encodeLEInt(s3 + mix192_3(s6, s7), out, off + 12)
        encodeLEInt(s4 + mix192_4(s6, s7), out, off + 16)
        encodeLEInt(s5 + mix192_5(s6, s7), out, off + 20)
    }

    private fun write224(out: ByteArray, off: Int) {
        encodeLEInt(s0 + (s7 ushr 27 and 0x1F), out, off)
        encodeLEInt(s1 + (s7 ushr 22 and 0x1F), out, off + 4)
        encodeLEInt(s2 + (s7 ushr 18 and 0x0F), out, off + 8)
        encodeLEInt(s3 + (s7 ushr 13 and 0x1F), out, off + 12)
        encodeLEInt(s4 + (s7 ushr 9 and 0x0F), out, off + 16)
        encodeLEInt(s5 + (s7 ushr 4 and 0x1F), out, off + 20)
        encodeLEInt(s6 + (s7 and 0x0F), out, off + 24)
    }

    private fun write256(out: ByteArray, off: Int) {
        encodeLEInt(s0, out, off)
        encodeLEInt(s1, out, off + 4)
        encodeLEInt(s2, out, off + 8)
        encodeLEInt(s3, out, off + 12)
        encodeLEInt(s4, out, off + 16)
        encodeLEInt(s5, out, off + 20)
        encodeLEInt(s6, out, off + 24)
        encodeLEInt(s7, out, off + 28)
    }

    private fun writeOutput(out: ByteArray, off: Int) {
        when (olen) {
            4 -> write128(out, off)
            5 -> write160(out, off)
            6 -> write192(out, off)
            7 -> write224(out, off)
            8 -> write256(out, off)
        }
    }

    override fun toString(): String {
        return "HAVAL-" + passes + "-" + (olen shl 5)
    }

    companion object {
        private val K2 = intArrayOf(
            0x452821E6, 0x38D01377, -0x41ab9931, 0x34E90C6C,
            -0x3f53d649, -0x3683af23, 0x3F84D5B5, -0x4ab8f6e9,
            -0x6de92a27, -0x768604e5, -0x2ecef45a, -0x67204a54,
            0x2FFD72DB, -0x2fe52049, -0x471e5013, 0x6A267E96,
            -0x45836fbb, -0xed38067, 0x24A19947, -0x4c6e9309,
            0x0801F2E2, -0x7a7103ea, 0x636920D8, 0x71574E69,
            -0x5ba7015d, -0xb6cc282, 0x0D95748F, 0x728EB658,
            0x718BCD58, -0x7deab512, 0x7B54A41D, -0x3da5a64b
        )
        private val K3 = intArrayOf(
            -0x63cf2ac7, 0x2AF26013, -0x3a2e4fdd, 0x286085F0,
            -0x35be86e8, -0x4724c711, -0x71862350, 0x603A180E,
            0x6C9E0E8B, -0x4fe175c2, -0x28ea883f, -0x42ceb4d9,
            0x78AF2FDA, 0x55605C60, -0x19aada0d, -0x55aa546c,
            0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6,
            -0x4b33a3cc, 0x1141E8CE, -0x5eab7951, 0x7C72E993,
            -0x4c11ebef, 0x636FBC2A, 0x2BA9C55D, 0x741831F6,
            -0x31a3c1ea, -0x64786ce2, -0x502945cd, 0x6C24CF5C
        )
        private val K4 = intArrayOf(
            0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF,
            -0x3b4017e5, 0x66282193, 0x61D809CC, -0x4de566f,
            0x487CAC60, 0x5DEC8032, -0x107ba2a3, -0x167a8a4f,
            -0x23d9dcfe, -0x149ae478, 0x23893E81, -0x2c69533b,
            0x0F6D6FF3, -0x7c0bbdc7, 0x2E0B4482, -0x5b7bdffc,
            0x69C8F04A, -0x61e064a2, 0x21C66842, -0x9169366,
            0x670C9C61, -0x542c7710, 0x6A51A0D2, -0x27abd098,
            -0x69f058d8, -0x54aecc5d, 0x6EEF0B6C, 0x137A3BE4
        )
        private val K5 = intArrayOf(
            -0x45c40fb0, 0x7EFB2A98, -0x5e0e9ae3, 0x39AF0176,
            0x66CA593E, -0x7dbcf178, -0x731179e7, 0x456F9FB4,
            0x7D84A5C3, 0x3B8B5EBE, -0x1f908a28, -0x7a3edf8d,
            0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
            0x1BFEDF72, 0x429B023D, 0x37D0D724, -0x2ff5edb8,
            -0x24f0152d, 0x49F1C09B, 0x075372C9, -0x7f66e485,
            0x25D479D8, -0x9172109, -0x1c01afe6, -0x4986b3c5,
            -0x68931f43, 0x04C006BA, -0x3e56b04a, 0x409F60C4
        )
        private val wp2 = intArrayOf(
            5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
            30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27
        )
        private val wp3 = intArrayOf(
            19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
            31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2
        )
        private val wp4 = intArrayOf(
            24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
            22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13
        )
        private val wp5 = intArrayOf(
            27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
            5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15
        )

        @Suppress("LongParameterList")
        private fun f1(x6: Int, x5: Int, x4: Int, x3: Int, x2: Int, x1: Int, x0: Int): Int {
            return x1 and x4 xor (x2 and x5) xor (x3 and x6) xor (x0 and x1) xor x0
        }

        @Suppress("LongParameterList")
        private fun f2(x6: Int, x5: Int, x4: Int, x3: Int, x2: Int, x1: Int, x0: Int): Int {
            return (x2 and (x1 and x3.inv() xor (x4 and x5) xor x6 xor x0)
                    xor (x4 and (x1 xor x5)) xor (x3 and x5 xor x0))
        }

        @Suppress("LongParameterList")
        private fun f3(x6: Int, x5: Int, x4: Int, x3: Int, x2: Int, x1: Int, x0: Int): Int {
            return (x3 and (x1 and x2 xor x6 xor x0)
                    xor (x1 and x4) xor (x2 and x5) xor x0)
        }

        @Suppress("LongParameterList")
        private fun f4(x6: Int, x5: Int, x4: Int, x3: Int, x2: Int, x1: Int, x0: Int): Int {
            return (x3 and (x1 and x2 xor (x4 or x6) xor x5)
                    xor (x4 and (x2.inv() and x5 xor x1 xor x6 xor x0)) xor (x2 and x6) xor x0)
        }

        @Suppress("LongParameterList")
        private fun f5(x6: Int, x5: Int, x4: Int, x3: Int, x2: Int, x1: Int, x0: Int): Int {
            return (x0 and (x1 and x2 and x3 xor x5).inv()
                    xor (x1 and x4) xor (x2 and x5) xor (x3 and x6))
        }

        private fun mix128(a0: Int, a1: Int, a2: Int, a3: Int, n: Int): Int {
            var tmp = (a0 and 0x000000FF
                    or (a1 and 0x0000FF00)
                    or (a2 and 0x00FF0000)
                    or (a3 and -0x1000000))
            if (n > 0) tmp = circularLeftInt(tmp, n)
            return tmp
        }

        @Suppress("FunctionName")
        private fun mix160_0(x5: Int, x6: Int, x7: Int): Int {
            return circularLeftInt(
                x5 and 0x01F80000
                        or (x6 and -0x2000000) or (x7 and 0x0000003F), 13
            )
        }

        @Suppress("FunctionName")
        private fun mix160_1(x5: Int, x6: Int, x7: Int): Int {
            return circularLeftInt(
                x5 and -0x2000000
                        or (x6 and 0x0000003F) or (x7 and 0x00000FC0), 7
            )
        }

        @Suppress("FunctionName")
        private fun mix160_2(x5: Int, x6: Int, x7: Int): Int {
            return (x5 and 0x0000003F
                    or (x6 and 0x00000FC0)
                    or (x7 and 0x0007F000))
        }

        @Suppress("FunctionName")
        private fun mix160_3(x5: Int, x6: Int, x7: Int): Int {
            return (x5 and 0x00000FC0
                    or (x6 and 0x0007F000)
                    or (x7 and 0x01F80000)) ushr 6
        }

        @Suppress("FunctionName")
        private fun mix160_4(x5: Int, x6: Int, x7: Int): Int {
            return (x5 and 0x0007F000
                    or (x6 and 0x01F80000)
                    or (x7 and -0x2000000)) ushr 12
        }

        @Suppress("FunctionName")
        private fun mix192_0(x6: Int, x7: Int): Int {
            return circularLeftInt(x6 and -0x4000000 or (x7 and 0x0000001F), 6)
        }

        @Suppress("FunctionName")
        private fun mix192_1(x6: Int, x7: Int): Int {
            return x6 and 0x0000001F or (x7 and 0x000003E0)
        }

        @Suppress("FunctionName")
        private fun mix192_2(x6: Int, x7: Int): Int {
            return x6 and 0x000003E0 or (x7 and 0x0000FC00) ushr 5
        }

        @Suppress("FunctionName")
        private fun mix192_3(x6: Int, x7: Int): Int {
            return x6 and 0x0000FC00 or (x7 and 0x001F0000) ushr 10
        }

        @Suppress("FunctionName")
        private fun mix192_4(x6: Int, x7: Int): Int {
            return x6 and 0x001F0000 or (x7 and 0x03E00000) ushr 16
        }

        @Suppress("FunctionName")
        private fun mix192_5(x6: Int, x7: Int): Int {
            return x6 and 0x03E00000 or (x7 and -0x4000000) ushr 21
        }
    }

    override val digestLength: Int
        get() = outputLength shr 3

    override fun copy() = copyState(HAVALCore(outputLength, passes))
}
