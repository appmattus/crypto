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
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 *
 * This class implements the MD4 digest algorithm under the
 * [Digest] API, using the [DigestEngine] class.
 * MD4 is described in RFC 1320.
 *
 * @version $Revision: 241 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal class MD4 : MDHelper<MD4>(true, 8) {

    private lateinit var currentVal: IntArray

    override fun copy(): MD4 {
        val d = MD4()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 16

    override val blockLength: Int
        get() = Algorithm.MD4.blockLength

    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..3) encodeLEInt(currentVal[i], output, outputOffset + 4 * i)
    }

    override fun doInit() {
        currentVal = IntArray(4)
        engineReset()
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    override fun processBlock(data: ByteArray) {
        /*
         * This method could have been made simpler by using
         * external methods for 32-bit decoding, or the round
         * functions F, G and H. However, it seems that the JIT
         * compiler from Sun's JDK decides not to inline those
         * methods, although it could (they are private final,
         * hence cannot be overridden) and it would yield better
         * performance.
         */
        var a = currentVal[0]
        var b = currentVal[1]
        var c = currentVal[2]
        var d = currentVal[3]
        val x00 = decodeLEInt(data, 0)
        val x01 = decodeLEInt(data, 4)
        val x02 = decodeLEInt(data, 8)
        val x03 = decodeLEInt(data, 12)
        val x04 = decodeLEInt(data, 16)
        val x05 = decodeLEInt(data, 20)
        val x06 = decodeLEInt(data, 24)
        val x07 = decodeLEInt(data, 28)
        val x08 = decodeLEInt(data, 32)
        val x09 = decodeLEInt(data, 36)
        val x10 = decodeLEInt(data, 40)
        val x11 = decodeLEInt(data, 44)
        val x12 = decodeLEInt(data, 48)
        val x13 = decodeLEInt(data, 52)
        val x14 = decodeLEInt(data, 56)
        val x15 = decodeLEInt(data, 60)
        var t: Int
        t = a + (c xor d and b xor d) + x00
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (b xor c and a xor c) + x01
        d = t shl 7 or (t ushr 32 - 7)
        t = c + (a xor b and d xor b) + x02
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (d xor a and c xor a) + x03
        b = t shl 19 or (t ushr 32 - 19)
        t = a + (c xor d and b xor d) + x04
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (b xor c and a xor c) + x05
        d = t shl 7 or (t ushr 32 - 7)
        t = c + (a xor b and d xor b) + x06
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (d xor a and c xor a) + x07
        b = t shl 19 or (t ushr 32 - 19)
        t = a + (c xor d and b xor d) + x08
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (b xor c and a xor c) + x09
        d = t shl 7 or (t ushr 32 - 7)
        t = c + (a xor b and d xor b) + x10
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (d xor a and c xor a) + x11
        b = t shl 19 or (t ushr 32 - 19)
        t = a + (c xor d and b xor d) + x12
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (b xor c and a xor c) + x13
        d = t shl 7 or (t ushr 32 - 7)
        t = c + (a xor b and d xor b) + x14
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (d xor a and c xor a) + x15
        b = t shl 19 or (t ushr 32 - 19)
        t = a + (d and c or (d or c and b)) + x00 + 0x5A827999
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (c and b or (c or b and a)) + x04 + 0x5A827999
        d = t shl 5 or (t ushr 32 - 5)
        t = c + (b and a or (b or a and d)) + x08 + 0x5A827999
        c = t shl 9 or (t ushr 32 - 9)
        t = b + (a and d or (a or d and c)) + x12 + 0x5A827999
        b = t shl 13 or (t ushr 32 - 13)
        t = a + (d and c or (d or c and b)) + x01 + 0x5A827999
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (c and b or (c or b and a)) + x05 + 0x5A827999
        d = t shl 5 or (t ushr 32 - 5)
        t = c + (b and a or (b or a and d)) + x09 + 0x5A827999
        c = t shl 9 or (t ushr 32 - 9)
        t = b + (a and d or (a or d and c)) + x13 + 0x5A827999
        b = t shl 13 or (t ushr 32 - 13)
        t = a + (d and c or (d or c and b)) + x02 + 0x5A827999
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (c and b or (c or b and a)) + x06 + 0x5A827999
        d = t shl 5 or (t ushr 32 - 5)
        t = c + (b and a or (b or a and d)) + x10 + 0x5A827999
        c = t shl 9 or (t ushr 32 - 9)
        t = b + (a and d or (a or d and c)) + x14 + 0x5A827999
        b = t shl 13 or (t ushr 32 - 13)
        t = a + (d and c or (d or c and b)) + x03 + 0x5A827999
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (c and b or (c or b and a)) + x07 + 0x5A827999
        d = t shl 5 or (t ushr 32 - 5)
        t = c + (b and a or (b or a and d)) + x11 + 0x5A827999
        c = t shl 9 or (t ushr 32 - 9)
        t = b + (a and d or (a or d and c)) + x15 + 0x5A827999
        b = t shl 13 or (t ushr 32 - 13)
        t = a + (b xor c xor d) + x00 + 0x6ED9EBA1
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (a xor b xor c) + x08 + 0x6ED9EBA1
        d = t shl 9 or (t ushr 32 - 9)
        t = c + (d xor a xor b) + x04 + 0x6ED9EBA1
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (c xor d xor a) + x12 + 0x6ED9EBA1
        b = t shl 15 or (t ushr 32 - 15)
        t = a + (b xor c xor d) + x02 + 0x6ED9EBA1
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (a xor b xor c) + x10 + 0x6ED9EBA1
        d = t shl 9 or (t ushr 32 - 9)
        t = c + (d xor a xor b) + x06 + 0x6ED9EBA1
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (c xor d xor a) + x14 + 0x6ED9EBA1
        b = t shl 15 or (t ushr 32 - 15)
        t = a + (b xor c xor d) + x01 + 0x6ED9EBA1
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (a xor b xor c) + x09 + 0x6ED9EBA1
        d = t shl 9 or (t ushr 32 - 9)
        t = c + (d xor a xor b) + x05 + 0x6ED9EBA1
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (c xor d xor a) + x13 + 0x6ED9EBA1
        b = t shl 15 or (t ushr 32 - 15)
        t = a + (b xor c xor d) + x03 + 0x6ED9EBA1
        a = t shl 3 or (t ushr 32 - 3)
        t = d + (a xor b xor c) + x11 + 0x6ED9EBA1
        d = t shl 9 or (t ushr 32 - 9)
        t = c + (d xor a xor b) + x07 + 0x6ED9EBA1
        c = t shl 11 or (t ushr 32 - 11)
        t = b + (c xor d xor a) + x15 + 0x6ED9EBA1
        b = t shl 15 or (t ushr 32 - 15)
        currentVal[0] += a
        currentVal[1] += b
        currentVal[2] += c
        currentVal[3] += d
    }

    override fun toString() = Algorithm.MD4.algorithmName
}
