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
import com.appmattus.crypto.internal.core.decodeBEInt
import com.appmattus.crypto.internal.core.encodeBEInt

/**
 *
 * This class implements the SHA-1 digest algorithm under the
 * [Digest] API. SHA-1 is defined by FIPS 180-2.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class SHA1 : MDHelper<SHA1>(false, 8) {
    private lateinit var currentVal: IntArray

    override fun copy(): SHA1 {
        val d = SHA1()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 20

    override val blockLength: Int
        get() = Algorithm.SHA_1.blockLength

    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
        currentVal[4] = -0x3c2d1e10
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..4) encodeBEInt(
            currentVal[i],
            output, outputOffset + 4 * i
        )
    }

    override fun doInit() {
        currentVal = IntArray(5)
        engineReset()
    }

    @Suppress("LongMethod")
    override fun processBlock(data: ByteArray) {
        var a = currentVal[0]
        var b = currentVal[1]
        var c = currentVal[2]
        var d = currentVal[3]
        var e = currentVal[4]
        var u: Int
        var w0 = decodeBEInt(data, 0)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b.inv() and d)) +
                e + w0 + 0x5A827999)
        b = b shl 30 or (b ushr 2)
        var w1 = decodeBEInt(data, 4)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a.inv() and c)) +
                d + w1 + 0x5A827999)
        a = a shl 30 or (a ushr 2)
        var w2 = decodeBEInt(data, 8)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e.inv() and b)) +
                c + w2 + 0x5A827999)
        e = e shl 30 or (e ushr 2)
        var w3 = decodeBEInt(data, 12)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d.inv() and a)) +
                b + w3 + 0x5A827999)
        d = d shl 30 or (d ushr 2)
        var w4 = decodeBEInt(data, 16)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c.inv() and e)) +
                a + w4 + 0x5A827999)
        c = c shl 30 or (c ushr 2)
        var w5 = decodeBEInt(data, 20)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b.inv() and d)) +
                e + w5 + 0x5A827999)
        b = b shl 30 or (b ushr 2)
        var w6 = decodeBEInt(data, 24)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a.inv() and c)) +
                d + w6 + 0x5A827999)
        a = a shl 30 or (a ushr 2)
        var w7 = decodeBEInt(data, 28)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e.inv() and b)) +
                c + w7 + 0x5A827999)
        e = e shl 30 or (e ushr 2)
        var w8 = decodeBEInt(data, 32)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d.inv() and a)) +
                b + w8 + 0x5A827999)
        d = d shl 30 or (d ushr 2)
        var w9 = decodeBEInt(data, 36)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c.inv() and e)) +
                a + w9 + 0x5A827999)
        c = c shl 30 or (c ushr 2)
        var wa = decodeBEInt(data, 40)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b.inv() and d)) +
                e + wa + 0x5A827999)
        b = b shl 30 or (b ushr 2)
        var wb = decodeBEInt(data, 44)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a.inv() and c)) +
                d + wb + 0x5A827999)
        a = a shl 30 or (a ushr 2)
        var wc = decodeBEInt(data, 48)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e.inv() and b)) +
                c + wc + 0x5A827999)
        e = e shl 30 or (e ushr 2)
        var wd = decodeBEInt(data, 52)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d.inv() and a)) +
                b + wd + 0x5A827999)
        d = d shl 30 or (d ushr 2)
        var we = decodeBEInt(data, 56)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c.inv() and e)) +
                a + we + 0x5A827999)
        c = c shl 30 or (c ushr 2)
        var wf = decodeBEInt(data, 60)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b.inv() and d)) +
                e + wf + 0x5A827999)
        b = b shl 30 or (b ushr 2)
        u = wd xor w8 xor w2 xor w0
        w0 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a.inv() and c)) +
                d + w0 + 0x5A827999)
        a = a shl 30 or (a ushr 2)
        u = we xor w9 xor w3 xor w1
        w1 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e.inv() and b)) +
                c + w1 + 0x5A827999)
        e = e shl 30 or (e ushr 2)
        u = wf xor wa xor w4 xor w2
        w2 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d.inv() and a)) +
                b + w2 + 0x5A827999)
        d = d shl 30 or (d ushr 2)
        u = w0 xor wb xor w5 xor w3
        w3 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c.inv() and e)) +
                a + w3 + 0x5A827999)
        c = c shl 30 or (c ushr 2)
        u = w1 xor wc xor w6 xor w4
        w4 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + w4 + 0x6ED9EBA1)
        b = b shl 30 or (b ushr 2)
        u = w2 xor wd xor w7 xor w5
        w5 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + w5 + 0x6ED9EBA1)
        a = a shl 30 or (a ushr 2)
        u = w3 xor we xor w8 xor w6
        w6 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + w6 + 0x6ED9EBA1)
        e = e shl 30 or (e ushr 2)
        u = w4 xor wf xor w9 xor w7
        w7 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + w7 + 0x6ED9EBA1)
        d = d shl 30 or (d ushr 2)
        u = w5 xor w0 xor wa xor w8
        w8 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + w8 + 0x6ED9EBA1)
        c = c shl 30 or (c ushr 2)
        u = w6 xor w1 xor wb xor w9
        w9 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + w9 + 0x6ED9EBA1)
        b = b shl 30 or (b ushr 2)
        u = w7 xor w2 xor wc xor wa
        wa = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + wa + 0x6ED9EBA1)
        a = a shl 30 or (a ushr 2)
        u = w8 xor w3 xor wd xor wb
        wb = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + wb + 0x6ED9EBA1)
        e = e shl 30 or (e ushr 2)
        u = w9 xor w4 xor we xor wc
        wc = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + wc + 0x6ED9EBA1)
        d = d shl 30 or (d ushr 2)
        u = wa xor w5 xor wf xor wd
        wd = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + wd + 0x6ED9EBA1)
        c = c shl 30 or (c ushr 2)
        u = wb xor w6 xor w0 xor we
        we = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + we + 0x6ED9EBA1)
        b = b shl 30 or (b ushr 2)
        u = wc xor w7 xor w1 xor wf
        wf = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + wf + 0x6ED9EBA1)
        a = a shl 30 or (a ushr 2)
        u = wd xor w8 xor w2 xor w0
        w0 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + w0 + 0x6ED9EBA1)
        e = e shl 30 or (e ushr 2)
        u = we xor w9 xor w3 xor w1
        w1 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + w1 + 0x6ED9EBA1)
        d = d shl 30 or (d ushr 2)
        u = wf xor wa xor w4 xor w2
        w2 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + w2 + 0x6ED9EBA1)
        c = c shl 30 or (c ushr 2)
        u = w0 xor wb xor w5 xor w3
        w3 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + w3 + 0x6ED9EBA1)
        b = b shl 30 or (b ushr 2)
        u = w1 xor wc xor w6 xor w4
        w4 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + w4 + 0x6ED9EBA1)
        a = a shl 30 or (a ushr 2)
        u = w2 xor wd xor w7 xor w5
        w5 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + w5 + 0x6ED9EBA1)
        e = e shl 30 or (e ushr 2)
        u = w3 xor we xor w8 xor w6
        w6 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + w6 + 0x6ED9EBA1)
        d = d shl 30 or (d ushr 2)
        u = w4 xor wf xor w9 xor w7
        w7 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + w7 + 0x6ED9EBA1)
        c = c shl 30 or (c ushr 2)
        u = w5 xor w0 xor wa xor w8
        w8 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b and d) or (c and d)) +
                e + w8 + -0x70e44324)
        b = b shl 30 or (b ushr 2)
        u = w6 xor w1 xor wb xor w9
        w9 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a and c) or (b and c)) +
                d + w9 + -0x70e44324)
        a = a shl 30 or (a ushr 2)
        u = w7 xor w2 xor wc xor wa
        wa = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e and b) or (a and b)) +
                c + wa + -0x70e44324)
        e = e shl 30 or (e ushr 2)
        u = w8 xor w3 xor wd xor wb
        wb = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d and a) or (e and a)) +
                b + wb + -0x70e44324)
        d = d shl 30 or (d ushr 2)
        u = w9 xor w4 xor we xor wc
        wc = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c and e) or (d and e)) +
                a + wc + -0x70e44324)
        c = c shl 30 or (c ushr 2)
        u = wa xor w5 xor wf xor wd
        wd = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b and d) or (c and d)) +
                e + wd + -0x70e44324)
        b = b shl 30 or (b ushr 2)
        u = wb xor w6 xor w0 xor we
        we = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a and c) or (b and c)) +
                d + we + -0x70e44324)
        a = a shl 30 or (a ushr 2)
        u = wc xor w7 xor w1 xor wf
        wf = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e and b) or (a and b)) +
                c + wf + -0x70e44324)
        e = e shl 30 or (e ushr 2)
        u = wd xor w8 xor w2 xor w0
        w0 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d and a) or (e and a)) +
                b + w0 + -0x70e44324)
        d = d shl 30 or (d ushr 2)
        u = we xor w9 xor w3 xor w1
        w1 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c and e) or (d and e)) +
                a + w1 + -0x70e44324)
        c = c shl 30 or (c ushr 2)
        u = wf xor wa xor w4 xor w2
        w2 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b and d) or (c and d)) +
                e + w2 + -0x70e44324)
        b = b shl 30 or (b ushr 2)
        u = w0 xor wb xor w5 xor w3
        w3 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a and c) or (b and c)) +
                d + w3 + -0x70e44324)
        a = a shl 30 or (a ushr 2)
        u = w1 xor wc xor w6 xor w4
        w4 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e and b) or (a and b)) +
                c + w4 + -0x70e44324)
        e = e shl 30 or (e ushr 2)
        u = w2 xor wd xor w7 xor w5
        w5 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d and a) or (e and a)) +
                b + w5 + -0x70e44324)
        d = d shl 30 or (d ushr 2)
        u = w3 xor we xor w8 xor w6
        w6 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c and e) or (d and e)) +
                a + w6 + -0x70e44324)
        c = c shl 30 or (c ushr 2)
        u = w4 xor wf xor w9 xor w7
        w7 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b and c or (b and d) or (c and d)) +
                e + w7 + -0x70e44324)
        b = b shl 30 or (b ushr 2)
        u = w5 xor w0 xor wa xor w8
        w8 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a and b or (a and c) or (b and c)) +
                d + w8 + -0x70e44324)
        a = a shl 30 or (a ushr 2)
        u = w6 xor w1 xor wb xor w9
        w9 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e and a or (e and b) or (a and b)) +
                c + w9 + -0x70e44324)
        e = e shl 30 or (e ushr 2)
        u = w7 xor w2 xor wc xor wa
        wa = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d and e or (d and a) or (e and a)) +
                b + wa + -0x70e44324)
        d = d shl 30 or (d ushr 2)
        u = w8 xor w3 xor wd xor wb
        wb = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c and d or (c and e) or (d and e)) +
                a + wb + -0x70e44324)
        c = c shl 30 or (c ushr 2)
        u = w9 xor w4 xor we xor wc
        wc = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + wc + -0x359d3e2a)
        b = b shl 30 or (b ushr 2)
        u = wa xor w5 xor wf xor wd
        wd = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + wd + -0x359d3e2a)
        a = a shl 30 or (a ushr 2)
        u = wb xor w6 xor w0 xor we
        we = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + we + -0x359d3e2a)
        e = e shl 30 or (e ushr 2)
        u = wc xor w7 xor w1 xor wf
        wf = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + wf + -0x359d3e2a)
        d = d shl 30 or (d ushr 2)
        u = wd xor w8 xor w2 xor w0
        w0 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + w0 + -0x359d3e2a)
        c = c shl 30 or (c ushr 2)
        u = we xor w9 xor w3 xor w1
        w1 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + w1 + -0x359d3e2a)
        b = b shl 30 or (b ushr 2)
        u = wf xor wa xor w4 xor w2
        w2 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + w2 + -0x359d3e2a)
        a = a shl 30 or (a ushr 2)
        u = w0 xor wb xor w5 xor w3
        w3 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + w3 + -0x359d3e2a)
        e = e shl 30 or (e ushr 2)
        u = w1 xor wc xor w6 xor w4
        w4 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + w4 + -0x359d3e2a)
        d = d shl 30 or (d ushr 2)
        u = w2 xor wd xor w7 xor w5
        w5 = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + w5 + -0x359d3e2a)
        c = c shl 30 or (c ushr 2)
        u = w3 xor we xor w8 xor w6
        w6 = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + w6 + -0x359d3e2a)
        b = b shl 30 or (b ushr 2)
        u = w4 xor wf xor w9 xor w7
        w7 = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + w7 + -0x359d3e2a)
        a = a shl 30 or (a ushr 2)
        u = w5 xor w0 xor wa xor w8
        w8 = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + w8 + -0x359d3e2a)
        e = e shl 30 or (e ushr 2)
        u = w6 xor w1 xor wb xor w9
        w9 = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + w9 + -0x359d3e2a)
        d = d shl 30 or (d ushr 2)
        u = w7 xor w2 xor wc xor wa
        wa = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + wa + -0x359d3e2a)
        c = c shl 30 or (c ushr 2)
        u = w8 xor w3 xor wd xor wb
        wb = u shl 1 or (u ushr 31)
        e = ((a shl 5 or (a ushr 27)) + (b xor c xor d) +
                e + wb + -0x359d3e2a)
        b = b shl 30 or (b ushr 2)
        u = w9 xor w4 xor we xor wc
        wc = u shl 1 or (u ushr 31)
        d = ((e shl 5 or (e ushr 27)) + (a xor b xor c) +
                d + wc + -0x359d3e2a)
        a = a shl 30 or (a ushr 2)
        u = wa xor w5 xor wf xor wd
        wd = u shl 1 or (u ushr 31)
        c = ((d shl 5 or (d ushr 27)) + (e xor a xor b) +
                c + wd + -0x359d3e2a)
        e = e shl 30 or (e ushr 2)
        u = wb xor w6 xor w0 xor we
        we = u shl 1 or (u ushr 31)
        b = ((c shl 5 or (c ushr 27)) + (d xor e xor a) +
                b + we + -0x359d3e2a)
        d = d shl 30 or (d ushr 2)
        u = wc xor w7 xor w1 xor wf
        wf = u shl 1 or (u ushr 31)
        a = ((b shl 5 or (b ushr 27)) + (c xor d xor e) +
                a + wf + -0x359d3e2a)
        c = c shl 30 or (c ushr 2)
        currentVal[0] += a
        currentVal[1] += b
        currentVal[2] += c
        currentVal[3] += d
        currentVal[4] += e
    }

    override fun toString() = Algorithm.SHA_1.algorithmName
}
