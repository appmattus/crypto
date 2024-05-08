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
 * Copyright 2021-2024 Appmattus Limited
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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 *
 * This class implements the RipeMD-160 digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal class RipeMD160 : MDHelper<RipeMD160>(true, 8) {

    private lateinit var currentVal: IntArray
    private lateinit var x: IntArray

    override fun copy(): RipeMD160 {
        val d = RipeMD160()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 20

    override val blockLength: Int
        get() = Algorithm.RipeMD160.blockLength

    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
        currentVal[4] = -0x3c2d1e10
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..4) encodeLEInt(currentVal[i], output, outputOffset + 4 * i)
    }

    override fun doInit() {
        currentVal = IntArray(5)
        x = IntArray(16)
        engineReset()
    }

    @Suppress("LongMethod")
    override fun processBlock(data: ByteArray) {
        val h0: Int
        val h1: Int
        val h2: Int
        val h3: Int
        val h4: Int
        var a1: Int
        var b1: Int
        var c1: Int
        var d1: Int
        var e1: Int
        var a2: Int
        var b2: Int
        var c2: Int
        var d2: Int
        var e2: Int
        a2 = currentVal[0]
        a1 = a2
        h0 = a1
        b2 = currentVal[1]
        b1 = b2
        h1 = b1
        c2 = currentVal[2]
        c1 = c2
        h2 = c1
        d2 = currentVal[3]
        d1 = d2
        h3 = d1
        e2 = currentVal[4]
        e1 = e2
        h4 = e1
        run {
            var i = 0
            var j = 0
            while (i < 16) {
                x[i] = decodeLEInt(data, j)
                i++
                j += 4
            }
        }
        for (i in 0..15) {
            var t1 = (a1 + (b1 xor c1 xor d1) + x[i])
            t1 = (t1 shl s1[i] or (t1 ushr 32 - s1[i])) + e1
            a1 = e1
            e1 = d1
            d1 = c1 shl 10 or (c1 ushr 22)
            c1 = b1
            b1 = t1
        }
        for (i in 16..31) {
            var t1 = (a1 + (c1 xor d1 and b1 xor d1) + x[r1[i]] + 0x5A827999)
            t1 = (t1 shl s1[i] or (t1 ushr 32 - s1[i])) + e1
            a1 = e1
            e1 = d1
            d1 = c1 shl 10 or (c1 ushr 22)
            c1 = b1
            b1 = t1
        }
        for (i in 32..47) {
            var t1 = (a1 + (b1 or c1.inv() xor d1) + x[r1[i]] + 0x6ED9EBA1)
            t1 = (t1 shl s1[i] or (t1 ushr 32 - s1[i])) + e1
            a1 = e1
            e1 = d1
            d1 = c1 shl 10 or (c1 ushr 22)
            c1 = b1
            b1 = t1
        }
        for (i in 48..63) {
            var t1 = (a1 + (b1 xor c1 and d1 xor c1) + x[r1[i]] + -0x70e44324)
            t1 = (t1 shl s1[i] or (t1 ushr 32 - s1[i])) + e1
            a1 = e1
            e1 = d1
            d1 = c1 shl 10 or (c1 ushr 22)
            c1 = b1
            b1 = t1
        }
        for (i in 64..79) {
            var t1 = (a1 + (b1 xor (c1 or d1.inv())) + x[r1[i]] + -0x56ac02b2)
            t1 = (t1 shl s1[i] or (t1 ushr 32 - s1[i])) + e1
            a1 = e1
            e1 = d1
            d1 = c1 shl 10 or (c1 ushr 22)
            c1 = b1
            b1 = t1
        }
        for (i in 0..15) {
            var t2 = (a2 + (b2 xor (c2 or d2.inv())) + x[r2[i]] + 0x50A28BE6)
            t2 = (t2 shl s2[i] or (t2 ushr 32 - s2[i])) + e2
            a2 = e2
            e2 = d2
            d2 = c2 shl 10 or (c2 ushr 22)
            c2 = b2
            b2 = t2
        }
        for (i in 16..31) {
            var t2 = (a2 + (b2 xor c2 and d2 xor c2) + x[r2[i]] + 0x5C4DD124)
            t2 = (t2 shl s2[i] or (t2 ushr 32 - s2[i])) + e2
            a2 = e2
            e2 = d2
            d2 = c2 shl 10 or (c2 ushr 22)
            c2 = b2
            b2 = t2
        }
        for (i in 32..47) {
            var t2 = (a2 + (b2 or c2.inv() xor d2) + x[r2[i]] + 0x6D703EF3)
            t2 = (t2 shl s2[i] or (t2 ushr 32 - s2[i])) + e2
            a2 = e2
            e2 = d2
            d2 = c2 shl 10 or (c2 ushr 22)
            c2 = b2
            b2 = t2
        }
        for (i in 48..63) {
            var t2 = (a2 + (c2 xor d2 and b2 xor d2) + x[r2[i]] + 0x7A6D76E9)
            t2 = (t2 shl s2[i] or (t2 ushr 32 - s2[i])) + e2
            a2 = e2
            e2 = d2
            d2 = c2 shl 10 or (c2 ushr 22)
            c2 = b2
            b2 = t2
        }
        for (i in 64..79) {
            var t2 = (a2 + (b2 xor c2 xor d2) + x[r2[i]])
            t2 = (t2 shl s2[i] or (t2 ushr 32 - s2[i])) + e2
            a2 = e2
            e2 = d2
            d2 = c2 shl 10 or (c2 ushr 22)
            c2 = b2
            b2 = t2
        }
        val t = h1 + c1 + d2
        currentVal[1] = h2 + d1 + e2
        currentVal[2] = h3 + e1 + a2
        currentVal[3] = h4 + a1 + b2
        currentVal[4] = h0 + b1 + c2
        currentVal[0] = t
    }

    override fun toString() = Algorithm.RipeMD160.algorithmName

    companion object {

        private val r1 = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
        )
        private val r2 = intArrayOf(
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
        )
        private val s1 = intArrayOf(
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
        )
        private val s2 = intArrayOf(
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
        )
    }
}
