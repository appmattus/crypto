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
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 *
 * This class implements the RadioGatun[64] digest algorithm under the
 * [Digest] API.
 *
 * @version $Revision: 232 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class RadioGatun64 : DigestEngine<RadioGatun64>() {
    private lateinit var a: LongArray
    private lateinit var b: LongArray

    override fun copy(): RadioGatun64 {
        val d = RadioGatun64()
        a.copyInto(d.a, 0, 0, a.size)
        b.copyInto(d.b, 0, 0, b.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 32

    override val blockLength: Int
        get() = Algorithm.RadioGatun64.blockLength

    override fun engineReset() {
        for (i in a.indices) a[i] = 0
        for (i in b.indices) b[i] = 0
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        var ptr = flush()
        val buf = blockBuffer
        buf[ptr++] = 0x01
        for (i in ptr..311) buf[i] = 0
        processBlock(buf)
        var num = 18
        while (true) {
            ptr += 24
            if (ptr > 312) break
            num--
        }
        blank(num, output, outputOffset)
    }

    override fun doInit() {
        a = LongArray(19)
        b = LongArray(39)
        engineReset()
    }

    @Suppress("ComplexMethod", "LongMethod")
    override fun processBlock(data: ByteArray) {
        var a00 = a[0]
        var a01 = a[1]
        var a02 = a[2]
        var a03 = a[3]
        var a04 = a[4]
        var a05 = a[5]
        var a06 = a[6]
        var a07 = a[7]
        var a08 = a[8]
        var a09 = a[9]
        var a10 = a[10]
        var a11 = a[11]
        var a12 = a[12]
        var a13 = a[13]
        var a14 = a[14]
        var a15 = a[15]
        var a16 = a[16]
        var a17 = a[17]
        var a18 = a[18]
        var dp = 0
        for (mk in 12 downTo 0) {
            val p0 = decodeLELong(data, dp + 0)
            val p1 = decodeLELong(data, dp + 8)
            val p2 = decodeLELong(data, dp + 16)
            dp += 24
            var bj = if (mk == 12) 0 else 3 * (mk + 1)
            b[bj + 0] = b[bj + 0] xor p0
            b[bj + 1] = b[bj + 1] xor p1
            b[bj + 2] = b[bj + 2] xor p2
            a16 = a16 xor p0
            a17 = a17 xor p1
            a18 = a18 xor p2
            bj = mk * 3
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 0] = b[bj + 0] xor a01
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 1] = b[bj + 1] xor a02
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 2] = b[bj + 2] xor a03
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 0] = b[bj + 0] xor a04
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 1] = b[bj + 1] xor a05
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 2] = b[bj + 2] xor a06
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 0] = b[bj + 0] xor a07
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 1] = b[bj + 1] xor a08
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 2] = b[bj + 2] xor a09
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 0] = b[bj + 0] xor a10
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 1] = b[bj + 1] xor a11
            if (3.let { bj += it; bj } == 39) bj = 0
            b[bj + 2] = b[bj + 2] xor a12
            var t00 = a00 xor (a01 or a02.inv())
            var t01 = a01 xor (a02 or a03.inv())
            var t02 = a02 xor (a03 or a04.inv())
            var t03 = a03 xor (a04 or a05.inv())
            var t04 = a04 xor (a05 or a06.inv())
            var t05 = a05 xor (a06 or a07.inv())
            var t06 = a06 xor (a07 or a08.inv())
            var t07 = a07 xor (a08 or a09.inv())
            var t08 = a08 xor (a09 or a10.inv())
            var t09 = a09 xor (a10 or a11.inv())
            var t10 = a10 xor (a11 or a12.inv())
            var t11 = a11 xor (a12 or a13.inv())
            var t12 = a12 xor (a13 or a14.inv())
            var t13 = a13 xor (a14 or a15.inv())
            var t14 = a14 xor (a15 or a16.inv())
            var t15 = a15 xor (a16 or a17.inv())
            var t16 = a16 xor (a17 or a18.inv())
            var t17 = a17 xor (a18 or a00.inv())
            var t18 = a18 xor (a00 or a01.inv())
            a00 = t00
            a01 = t07 shl 63 or (t07 ushr 1)
            a02 = t14 shl 61 or (t14 ushr 3)
            a03 = t02 shl 58 or (t02 ushr 6)
            a04 = t09 shl 54 or (t09 ushr 10)
            a05 = t16 shl 49 or (t16 ushr 15)
            a06 = t04 shl 43 or (t04 ushr 21)
            a07 = t11 shl 36 or (t11 ushr 28)
            a08 = t18 shl 28 or (t18 ushr 36)
            a09 = t06 shl 19 or (t06 ushr 45)
            a10 = t13 shl 9 or (t13 ushr 55)
            a11 = t01 shl 62 or (t01 ushr 2)
            a12 = t08 shl 50 or (t08 ushr 14)
            a13 = t15 shl 37 or (t15 ushr 27)
            a14 = t03 shl 23 or (t03 ushr 41)
            a15 = t10 shl 8 or (t10 ushr 56)
            a16 = t17 shl 56 or (t17 ushr 8)
            a17 = t05 shl 39 or (t05 ushr 25)
            a18 = t12 shl 21 or (t12 ushr 43)
            t00 = a00 xor a01 xor a04
            t01 = a01 xor a02 xor a05
            t02 = a02 xor a03 xor a06
            t03 = a03 xor a04 xor a07
            t04 = a04 xor a05 xor a08
            t05 = a05 xor a06 xor a09
            t06 = a06 xor a07 xor a10
            t07 = a07 xor a08 xor a11
            t08 = a08 xor a09 xor a12
            t09 = a09 xor a10 xor a13
            t10 = a10 xor a11 xor a14
            t11 = a11 xor a12 xor a15
            t12 = a12 xor a13 xor a16
            t13 = a13 xor a14 xor a17
            t14 = a14 xor a15 xor a18
            t15 = a15 xor a16 xor a00
            t16 = a16 xor a17 xor a01
            t17 = a17 xor a18 xor a02
            t18 = a18 xor a00 xor a03
            a00 = t00 xor 1
            a01 = t01
            a02 = t02
            a03 = t03
            a04 = t04
            a05 = t05
            a06 = t06
            a07 = t07
            a08 = t08
            a09 = t09
            a10 = t10
            a11 = t11
            a12 = t12
            a13 = t13
            a14 = t14
            a15 = t15
            a16 = t16
            a17 = t17
            a18 = t18
            bj = mk * 3
            a13 = a13 xor b[bj + 0]
            a14 = a14 xor b[bj + 1]
            a15 = a15 xor b[bj + 2]
        }
        a[0] = a00
        a[1] = a01
        a[2] = a02
        a[3] = a03
        a[4] = a04
        a[5] = a05
        a[6] = a06
        a[7] = a07
        a[8] = a08
        a[9] = a09
        a[10] = a10
        a[11] = a11
        a[12] = a12
        a[13] = a13
        a[14] = a14
        a[15] = a15
        a[16] = a16
        a[17] = a17
        a[18] = a18
    }

    /**
     * Run `num` blank rounds. For the last four rounds,
     * `a[1]` and `a[2]` are written out in `out`,
     * beginning at offset `off`. This method does not write
     * back all the state; thus, it must be the final operation in a
     * given hash function computation.
     *
     * @param num   the number of blank rounds
     * @param out   the output buffer
     * @param off   the output offset
     */
    @Suppress("NAME_SHADOWING", "LongMethod")
    private fun blank(num: Int, out: ByteArray, off: Int) {
        var num = num
        var off = off
        var a00 = a[0]
        var a01 = a[1]
        var a02 = a[2]
        var a03 = a[3]
        var a04 = a[4]
        var a05 = a[5]
        var a06 = a[6]
        var a07 = a[7]
        var a08 = a[8]
        var a09 = a[9]
        var a10 = a[10]
        var a11 = a[11]
        var a12 = a[12]
        var a13 = a[13]
        var a14 = a[14]
        var a15 = a[15]
        var a16 = a[16]
        var a17 = a[17]
        var a18 = a[18]
        while (num-- > 0) {
            b[0] = b[0] xor a01
            b[4] = b[4] xor a02
            b[8] = b[8] xor a03
            b[9] = b[9] xor a04
            b[13] = b[13] xor a05
            b[17] = b[17] xor a06
            b[18] = b[18] xor a07
            b[22] = b[22] xor a08
            b[26] = b[26] xor a09
            b[27] = b[27] xor a10
            b[31] = b[31] xor a11
            b[35] = b[35] xor a12
            var t00 = a00 xor (a01 or a02.inv())
            var t01 = a01 xor (a02 or a03.inv())
            var t02 = a02 xor (a03 or a04.inv())
            var t03 = a03 xor (a04 or a05.inv())
            var t04 = a04 xor (a05 or a06.inv())
            var t05 = a05 xor (a06 or a07.inv())
            var t06 = a06 xor (a07 or a08.inv())
            var t07 = a07 xor (a08 or a09.inv())
            var t08 = a08 xor (a09 or a10.inv())
            var t09 = a09 xor (a10 or a11.inv())
            var t10 = a10 xor (a11 or a12.inv())
            var t11 = a11 xor (a12 or a13.inv())
            var t12 = a12 xor (a13 or a14.inv())
            var t13 = a13 xor (a14 or a15.inv())
            var t14 = a14 xor (a15 or a16.inv())
            var t15 = a15 xor (a16 or a17.inv())
            var t16 = a16 xor (a17 or a18.inv())
            var t17 = a17 xor (a18 or a00.inv())
            var t18 = a18 xor (a00 or a01.inv())
            a00 = t00
            a01 = t07 shl 63 or (t07 ushr 1)
            a02 = t14 shl 61 or (t14 ushr 3)
            a03 = t02 shl 58 or (t02 ushr 6)
            a04 = t09 shl 54 or (t09 ushr 10)
            a05 = t16 shl 49 or (t16 ushr 15)
            a06 = t04 shl 43 or (t04 ushr 21)
            a07 = t11 shl 36 or (t11 ushr 28)
            a08 = t18 shl 28 or (t18 ushr 36)
            a09 = t06 shl 19 or (t06 ushr 45)
            a10 = t13 shl 9 or (t13 ushr 55)
            a11 = t01 shl 62 or (t01 ushr 2)
            a12 = t08 shl 50 or (t08 ushr 14)
            a13 = t15 shl 37 or (t15 ushr 27)
            a14 = t03 shl 23 or (t03 ushr 41)
            a15 = t10 shl 8 or (t10 ushr 56)
            a16 = t17 shl 56 or (t17 ushr 8)
            a17 = t05 shl 39 or (t05 ushr 25)
            a18 = t12 shl 21 or (t12 ushr 43)
            t00 = a00 xor a01 xor a04
            t01 = a01 xor a02 xor a05
            t02 = a02 xor a03 xor a06
            t03 = a03 xor a04 xor a07
            t04 = a04 xor a05 xor a08
            t05 = a05 xor a06 xor a09
            t06 = a06 xor a07 xor a10
            t07 = a07 xor a08 xor a11
            t08 = a08 xor a09 xor a12
            t09 = a09 xor a10 xor a13
            t10 = a10 xor a11 xor a14
            t11 = a11 xor a12 xor a15
            t12 = a12 xor a13 xor a16
            t13 = a13 xor a14 xor a17
            t14 = a14 xor a15 xor a18
            t15 = a15 xor a16 xor a00
            t16 = a16 xor a17 xor a01
            t17 = a17 xor a18 xor a02
            t18 = a18 xor a00 xor a03
            a00 = t00 xor 1
            a01 = t01
            a02 = t02
            a03 = t03
            a04 = t04
            a05 = t05
            a06 = t06
            a07 = t07
            a08 = t08
            a09 = t09
            a10 = t10
            a11 = t11
            a12 = t12
            a13 = t13
            a14 = t14
            a15 = t15
            a16 = t16
            a17 = t17
            a18 = t18
            val bt0 = b[36]
            val bt1 = b[37]
            val bt2 = b[38]
            a13 = a13 xor bt0
            a14 = a14 xor bt1
            a15 = a15 xor bt2
            b.copyInto(b, 3, 0, 36)
            b[0] = bt0
            b[1] = bt1
            b[2] = bt2
            if (num < 2) {
                encodeLELong(a01, out, off + 0)
                encodeLELong(a02, out, off + 8)
                off += 16
            }
        }

        /* not needed
		a[ 0] = a00;
		a[ 1] = a01;
		a[ 2] = a02;
		a[ 3] = a03;
		a[ 4] = a04;
		a[ 5] = a05;
		a[ 6] = a06;
		a[ 7] = a07;
		a[ 8] = a08;
		a[ 9] = a09;
		a[10] = a10;
		a[11] = a11;
		a[12] = a12;
		a[13] = a13;
		a[14] = a14;
		a[15] = a15;
		a[16] = a16;
		a[17] = a17;
		a[18] = a18;
		*/
    }

    override fun toString() = Algorithm.RadioGatun64.algorithmName
}
