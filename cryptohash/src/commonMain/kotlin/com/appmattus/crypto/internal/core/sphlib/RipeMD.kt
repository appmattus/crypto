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

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 *
 * This class implements the RipeMD digest algorithm under the [Digest] API. This is the original RipeMD, **not** the
 * strengthened variants RipeMD-128 or RipeMD-160. A collision for this
 * RipeMD has been published in 2004.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class RipeMD : MDHelper<RipeMD>(true, 8) {

    private lateinit var currentVal: IntArray
    private lateinit var x: IntArray

    override fun copy(): RipeMD {
        val d = RipeMD()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 16

    override val blockLength: Int
        get() = Algorithm.RipeMD.blockLength

    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..3) encodeLEInt(
            currentVal[i],
            output, outputOffset + 4 * i
        )
    }

    override fun doInit() {
        currentVal = IntArray(4)
        x = IntArray(16)
        engineReset()
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    override fun processBlock(data: ByteArray) {
        val h0: Int
        val h1: Int
        val h2: Int
        val h3: Int
        var a1: Int
        var b1: Int
        var c1: Int
        var d1: Int
        var a2: Int
        var b2: Int
        var c2: Int
        var d2: Int
        var tmp: Int
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
        var i = 0
        var j = 0
        while (i < 16) {
            x[i] = decodeLEInt(data, j)
            i++
            j += 4
        }
        tmp = a1 + (c1 xor d1 and b1 xor d1) + x[0]
        a1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d1 + (b1 xor c1 and a1 xor c1) + x[1]
        d1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = c1 + (a1 xor b1 and d1 xor b1) + x[2]
        c1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = b1 + (d1 xor a1 and c1 xor a1) + x[3]
        b1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = a1 + (c1 xor d1 and b1 xor d1) + x[4]
        a1 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = d1 + (b1 xor c1 and a1 xor c1) + x[5]
        d1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = c1 + (a1 xor b1 and d1 xor b1) + x[6]
        c1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = b1 + (d1 xor a1 and c1 xor a1) + x[7]
        b1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = a1 + (c1 xor d1 and b1 xor d1) + x[8]
        a1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d1 + (b1 xor c1 and a1 xor c1) + x[9]
        d1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = c1 + (a1 xor b1 and d1 xor b1) + x[10]
        c1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = b1 + (d1 xor a1 and c1 xor a1) + x[11]
        b1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = a1 + (c1 xor d1 and b1 xor d1) + x[12]
        a1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = d1 + (b1 xor c1 and a1 xor c1) + x[13]
        d1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = c1 + (a1 xor b1 and d1 xor b1) + x[14]
        c1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = b1 + (d1 xor a1 and c1 xor a1) + x[15]
        b1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = a1 + (b1 and c1 or (b1 or c1 and d1)) + x[7] + 0x5A827999
        a1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = d1 + (a1 and b1 or (a1 or b1 and c1)) + x[4] + 0x5A827999
        d1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = c1 + (d1 and a1 or (d1 or a1 and b1)) + x[13] + 0x5A827999
        c1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = b1 + (c1 and d1 or (c1 or d1 and a1)) + x[1] + 0x5A827999
        b1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = a1 + (b1 and c1 or (b1 or c1 and d1)) + x[10] + 0x5A827999
        a1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d1 + (a1 and b1 or (a1 or b1 and c1)) + x[6] + 0x5A827999
        d1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = c1 + (d1 and a1 or (d1 or a1 and b1)) + x[15] + 0x5A827999
        c1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = b1 + (c1 and d1 or (c1 or d1 and a1)) + x[3] + 0x5A827999
        b1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = a1 + (b1 and c1 or (b1 or c1 and d1)) + x[12] + 0x5A827999
        a1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = d1 + (a1 and b1 or (a1 or b1 and c1)) + x[0] + 0x5A827999
        d1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = c1 + (d1 and a1 or (d1 or a1 and b1)) + x[9] + 0x5A827999
        c1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = b1 + (c1 and d1 or (c1 or d1 and a1)) + x[5] + 0x5A827999
        b1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = a1 + (b1 and c1 or (b1 or c1 and d1)) + x[14] + 0x5A827999
        a1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = d1 + (a1 and b1 or (a1 or b1 and c1)) + x[2] + 0x5A827999
        d1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = c1 + (d1 and a1 or (d1 or a1 and b1)) + x[11] + 0x5A827999
        c1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = b1 + (c1 and d1 or (c1 or d1 and a1)) + x[8] + 0x5A827999
        b1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = a1 + (b1 xor c1 xor d1) + x[3] + 0x6ED9EBA1
        a1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d1 + (a1 xor b1 xor c1) + x[10] + 0x6ED9EBA1
        d1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = c1 + (d1 xor a1 xor b1) + x[2] + 0x6ED9EBA1
        c1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = b1 + (c1 xor d1 xor a1) + x[4] + 0x6ED9EBA1
        b1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = a1 + (b1 xor c1 xor d1) + x[9] + 0x6ED9EBA1
        a1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = d1 + (a1 xor b1 xor c1) + x[15] + 0x6ED9EBA1
        d1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = c1 + (d1 xor a1 xor b1) + x[8] + 0x6ED9EBA1
        c1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = b1 + (c1 xor d1 xor a1) + x[1] + 0x6ED9EBA1
        b1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = a1 + (b1 xor c1 xor d1) + x[14] + 0x6ED9EBA1
        a1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = d1 + (a1 xor b1 xor c1) + x[7] + 0x6ED9EBA1
        d1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = c1 + (d1 xor a1 xor b1) + x[0] + 0x6ED9EBA1
        c1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = b1 + (c1 xor d1 xor a1) + x[6] + 0x6ED9EBA1
        b1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = a1 + (b1 xor c1 xor d1) + x[11] + 0x6ED9EBA1
        a1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = d1 + (a1 xor b1 xor c1) + x[13] + 0x6ED9EBA1
        d1 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = c1 + (d1 xor a1 xor b1) + x[5] + 0x6ED9EBA1
        c1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = b1 + (c1 xor d1 xor a1) + x[12] + 0x6ED9EBA1
        b1 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = a2 + (c2 xor d2 and b2 xor d2) + x[0] + 0x50A28BE6
        a2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d2 + (b2 xor c2 and a2 xor c2) + x[1] + 0x50A28BE6
        d2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = c2 + (a2 xor b2 and d2 xor b2) + x[2] + 0x50A28BE6
        c2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = b2 + (d2 xor a2 and c2 xor a2) + x[3] + 0x50A28BE6
        b2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = a2 + (c2 xor d2 and b2 xor d2) + x[4] + 0x50A28BE6
        a2 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = d2 + (b2 xor c2 and a2 xor c2) + x[5] + 0x50A28BE6
        d2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = c2 + (a2 xor b2 and d2 xor b2) + x[6] + 0x50A28BE6
        c2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = b2 + (d2 xor a2 and c2 xor a2) + x[7] + 0x50A28BE6
        b2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = a2 + (c2 xor d2 and b2 xor d2) + x[8] + 0x50A28BE6
        a2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d2 + (b2 xor c2 and a2 xor c2) + x[9] + 0x50A28BE6
        d2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = c2 + (a2 xor b2 and d2 xor b2) + x[10] + 0x50A28BE6
        c2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = b2 + (d2 xor a2 and c2 xor a2) + x[11] + 0x50A28BE6
        b2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = a2 + (c2 xor d2 and b2 xor d2) + x[12] + 0x50A28BE6
        a2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = d2 + (b2 xor c2 and a2 xor c2) + x[13] + 0x50A28BE6
        d2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = c2 + (a2 xor b2 and d2 xor b2) + x[14] + 0x50A28BE6
        c2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = b2 + (d2 xor a2 and c2 xor a2) + x[15] + 0x50A28BE6
        b2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = a2 + (b2 and c2 or (b2 or c2 and d2)) + x[7]
        a2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = d2 + (a2 and b2 or (a2 or b2 and c2)) + x[4]
        d2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = c2 + (d2 and a2 or (d2 or a2 and b2)) + x[13]
        c2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = b2 + (c2 and d2 or (c2 or d2 and a2)) + x[1]
        b2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = a2 + (b2 and c2 or (b2 or c2 and d2)) + x[10]
        a2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d2 + (a2 and b2 or (a2 or b2 and c2)) + x[6]
        d2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = c2 + (d2 and a2 or (d2 or a2 and b2)) + x[15]
        c2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = b2 + (c2 and d2 or (c2 or d2 and a2)) + x[3]
        b2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = a2 + (b2 and c2 or (b2 or c2 and d2)) + x[12]
        a2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = d2 + (a2 and b2 or (a2 or b2 and c2)) + x[0]
        d2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = c2 + (d2 and a2 or (d2 or a2 and b2)) + x[9]
        c2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = b2 + (c2 and d2 or (c2 or d2 and a2)) + x[5]
        b2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = a2 + (b2 and c2 or (b2 or c2 and d2)) + x[14]
        a2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = d2 + (a2 and b2 or (a2 or b2 and c2)) + x[2]
        d2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = c2 + (d2 and a2 or (d2 or a2 and b2)) + x[11]
        c2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = b2 + (c2 and d2 or (c2 or d2 and a2)) + x[8]
        b2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = a2 + (b2 xor c2 xor d2) + x[3] + 0x5C4DD124
        a2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = d2 + (a2 xor b2 xor c2) + x[10] + 0x5C4DD124
        d2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = c2 + (d2 xor a2 xor b2) + x[2] + 0x5C4DD124
        c2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = b2 + (c2 xor d2 xor a2) + x[4] + 0x5C4DD124
        b2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = a2 + (b2 xor c2 xor d2) + x[9] + 0x5C4DD124
        a2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = d2 + (a2 xor b2 xor c2) + x[15] + 0x5C4DD124
        d2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = c2 + (d2 xor a2 xor b2) + x[8] + 0x5C4DD124
        c2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = b2 + (c2 xor d2 xor a2) + x[1] + 0x5C4DD124
        b2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = a2 + (b2 xor c2 xor d2) + x[14] + 0x5C4DD124
        a2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = d2 + (a2 xor b2 xor c2) + x[7] + 0x5C4DD124
        d2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = c2 + (d2 xor a2 xor b2) + x[0] + 0x5C4DD124
        c2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = b2 + (c2 xor d2 xor a2) + x[6] + 0x5C4DD124
        b2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = a2 + (b2 xor c2 xor d2) + x[11] + 0x5C4DD124
        a2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = d2 + (a2 xor b2 xor c2) + x[13] + 0x5C4DD124
        d2 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = c2 + (d2 xor a2 xor b2) + x[5] + 0x5C4DD124
        c2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = b2 + (c2 xor d2 xor a2) + x[12] + 0x5C4DD124
        b2 = tmp shl 5 or (tmp ushr 32 - 5)
        val t = h1 + c1 + d2
        currentVal[1] = h2 + d1 + a2
        currentVal[2] = h3 + a1 + b2
        currentVal[3] = h0 + b1 + c2
        currentVal[0] = t
    }

    override fun toString() = Algorithm.RipeMD.algorithmName
}
