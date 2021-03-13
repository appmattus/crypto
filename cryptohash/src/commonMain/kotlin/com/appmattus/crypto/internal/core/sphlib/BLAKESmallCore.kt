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

import com.appmattus.crypto.internal.core.circularRightInt
import com.appmattus.crypto.internal.core.decodeBEInt
import com.appmattus.crypto.internal.core.encodeBEInt
import kotlin.experimental.or

/**
 * This class implements BLAKE-224 and BLAKE-256, which differ only by
 * the IV, output length, and one bit in the padding.
 *
 * @version $Revision: 252 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class BLAKESmallCore<D : BLAKESmallCore<D>> : DigestEngine<D>() {

    private var h0 = 0
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0
    private var h5 = 0
    private var h6 = 0
    private var h7 = 0
    private var s0 = 0
    private var s1 = 0
    private var s2 = 0
    private var s3 = 0
    private var t0 = 0
    private var t1 = 0
    private lateinit var tmpM: IntArray
    private lateinit var tmpBuf: ByteArray

    override fun copyState(dest: D): D {
        dest.h0 = h0
        dest.h1 = h1
        dest.h2 = h2
        dest.h3 = h3
        dest.h4 = h4
        dest.h5 = h5
        dest.h6 = h6
        dest.h7 = h7
        dest.s0 = s0
        dest.s1 = s1
        dest.s2 = s2
        dest.s3 = s3
        dest.t0 = t0
        dest.t1 = t1
        return super.copyState(dest)
    }

    override fun engineReset() {
        val iv = initVal
        h0 = iv[0]
        h1 = iv[1]
        h2 = iv[2]
        h3 = iv[3]
        h4 = iv[4]
        h5 = iv[5]
        h6 = iv[6]
        h7 = iv[7]
        s3 = 0
        s2 = s3
        s1 = s2
        s0 = s1
        t1 = 0
        t0 = t1
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return the initial value (eight 32-bit words)
     */
    protected abstract val initVal: IntArray

    @Suppress("CascadeIf")
    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        val bitLen = ptr shl 3
        val th = t1
        val tl = t0 + bitLen
        tmpBuf[ptr] = 0x80.toByte()
        if (ptr == 0) {
            t0 = -0x200
            t1 = -0x1
        } else if (t0 == 0) {
            t0 = -0x200 + bitLen
            t1--
        } else {
            t0 -= 512 - bitLen
        }
        if (ptr < 56) {
            for (i in ptr + 1..55) tmpBuf[i] = 0x00
            if (digestLength == 32) tmpBuf[55] = tmpBuf[55] or 0x01
            encodeBEInt(th, tmpBuf, 56)
            encodeBEInt(tl, tmpBuf, 60)
            update(tmpBuf, ptr, 64 - ptr)
        } else {
            for (i in ptr + 1..63) tmpBuf[i] = 0
            update(tmpBuf, ptr, 64 - ptr)
            t0 = -0x200
            t1 = -0x1
            for (i in 0..55) tmpBuf[i] = 0x00
            if (digestLength == 32) tmpBuf[55] = 0x01
            encodeBEInt(th, tmpBuf, 56)
            encodeBEInt(tl, tmpBuf, 60)
            update(tmpBuf, 0, 64)
        }
        encodeBEInt(h0, output, outputOffset + 0)
        encodeBEInt(h1, output, outputOffset + 4)
        encodeBEInt(h2, output, outputOffset + 8)
        encodeBEInt(h3, output, outputOffset + 12)
        encodeBEInt(h4, output, outputOffset + 16)
        encodeBEInt(h5, output, outputOffset + 20)
        encodeBEInt(h6, output, outputOffset + 24)
        if (digestLength == 32) encodeBEInt(h7, output, outputOffset + 28)
    }

    override fun doInit() {
        tmpM = IntArray(16)
        tmpBuf = ByteArray(64)
        engineReset()
    }

    @Suppress("LongMethod")
    override fun processBlock(data: ByteArray) {
        t0 += 512
        if (t0 and 0x1FF.inv() == 0) t1++
        var v0 = h0
        var v1 = h1
        var v2 = h2
        var v3 = h3
        var v4 = h4
        var v5 = h5
        var v6 = h6
        var v7 = h7
        var v8 = s0 xor 0x243F6A88
        var v9 = s1 xor -0x7a5cf72d
        var vA = s2 xor 0x13198A2E
        var vB = s3 xor 0x03707344
        var vC = t0 xor -0x5bf6c7de
        var vD = t0 xor 0x299F31D0
        var vE = t1 xor 0x082EFA98
        var vF = t1 xor -0x13b19377
        val m = tmpM
        for (i in 0..15) m[i] = decodeBEInt(data, 4 * i)
        for (r in 0..13) {
            var o0 = SIGMA[(r shl 4) + 0x0]
            var o1 = SIGMA[(r shl 4) + 0x1]
            v0 += v4 + (m[o0] xor CS[o1])
            vC = circularRightInt(vC xor v0, 16)
            v8 += vC
            v4 = circularRightInt(v4 xor v8, 12)
            v0 += v4 + (m[o1] xor CS[o0])
            vC = circularRightInt(vC xor v0, 8)
            v8 += vC
            v4 = circularRightInt(v4 xor v8, 7)
            o0 = SIGMA[(r shl 4) + 0x2]
            o1 = SIGMA[(r shl 4) + 0x3]
            v1 += v5 + (m[o0] xor CS[o1])
            vD = circularRightInt(vD xor v1, 16)
            v9 += vD
            v5 = circularRightInt(v5 xor v9, 12)
            v1 += v5 + (m[o1] xor CS[o0])
            vD = circularRightInt(vD xor v1, 8)
            v9 += vD
            v5 = circularRightInt(v5 xor v9, 7)
            o0 = SIGMA[(r shl 4) + 0x4]
            o1 = SIGMA[(r shl 4) + 0x5]
            v2 += v6 + (m[o0] xor CS[o1])
            vE = circularRightInt(vE xor v2, 16)
            vA += vE
            v6 = circularRightInt(v6 xor vA, 12)
            v2 += v6 + (m[o1] xor CS[o0])
            vE = circularRightInt(vE xor v2, 8)
            vA += vE
            v6 = circularRightInt(v6 xor vA, 7)
            o0 = SIGMA[(r shl 4) + 0x6]
            o1 = SIGMA[(r shl 4) + 0x7]
            v3 += v7 + (m[o0] xor CS[o1])
            vF = circularRightInt(vF xor v3, 16)
            vB += vF
            v7 = circularRightInt(v7 xor vB, 12)
            v3 += v7 + (m[o1] xor CS[o0])
            vF = circularRightInt(vF xor v3, 8)
            vB += vF
            v7 = circularRightInt(v7 xor vB, 7)
            o0 = SIGMA[(r shl 4) + 0x8]
            o1 = SIGMA[(r shl 4) + 0x9]
            v0 += v5 + (m[o0] xor CS[o1])
            vF = circularRightInt(vF xor v0, 16)
            vA += vF
            v5 = circularRightInt(v5 xor vA, 12)
            v0 += v5 + (m[o1] xor CS[o0])
            vF = circularRightInt(vF xor v0, 8)
            vA += vF
            v5 = circularRightInt(v5 xor vA, 7)
            o0 = SIGMA[(r shl 4) + 0xA]
            o1 = SIGMA[(r shl 4) + 0xB]
            v1 += v6 + (m[o0] xor CS[o1])
            vC = circularRightInt(vC xor v1, 16)
            vB += vC
            v6 = circularRightInt(v6 xor vB, 12)
            v1 += v6 + (m[o1] xor CS[o0])
            vC = circularRightInt(vC xor v1, 8)
            vB += vC
            v6 = circularRightInt(v6 xor vB, 7)
            o0 = SIGMA[(r shl 4) + 0xC]
            o1 = SIGMA[(r shl 4) + 0xD]
            v2 += v7 + (m[o0] xor CS[o1])
            vD = circularRightInt(vD xor v2, 16)
            v8 += vD
            v7 = circularRightInt(v7 xor v8, 12)
            v2 += v7 + (m[o1] xor CS[o0])
            vD = circularRightInt(vD xor v2, 8)
            v8 += vD
            v7 = circularRightInt(v7 xor v8, 7)
            o0 = SIGMA[(r shl 4) + 0xE]
            o1 = SIGMA[(r shl 4) + 0xF]
            v3 += v4 + (m[o0] xor CS[o1])
            vE = circularRightInt(vE xor v3, 16)
            v9 += vE
            v4 = circularRightInt(v4 xor v9, 12)
            v3 += v4 + (m[o1] xor CS[o0])
            vE = circularRightInt(vE xor v3, 8)
            v9 += vE
            v4 = circularRightInt(v4 xor v9, 7)
        }
        h0 = h0 xor (s0 xor v0 xor v8)
        h1 = h1 xor (s1 xor v1 xor v9)
        h2 = h2 xor (s2 xor v2 xor vA)
        h3 = h3 xor (s3 xor v3 xor vB)
        h4 = h4 xor (s0 xor v4 xor vC)
        h5 = h5 xor (s1 xor v5 xor vD)
        h6 = h6 xor (s2 xor v6 xor vE)
        h7 = h7 xor (s3 xor v7 xor vF)
    }

    companion object {
        private val SIGMA = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
            12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
            13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
            6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
            10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8
        )
        private val CS = intArrayOf(
            0x243F6A88, -0x7a5cf72d, 0x13198A2E, 0x03707344,
            -0x5bf6c7de, 0x299F31D0, 0x082EFA98, -0x13b19377,
            0x452821E6, 0x38D01377, -0x41ab9931, 0x34E90C6C,
            -0x3f53d649, -0x3683af23, 0x3F84D5B5, -0x4ab8f6e9
        )
    }
}
