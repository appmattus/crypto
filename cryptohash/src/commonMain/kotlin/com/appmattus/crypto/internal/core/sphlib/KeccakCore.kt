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

import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * This class implements the core operations for the Keccak digest
 * algorithm.
 *
 * @version $Revision: 258 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class KeccakCore<D : KeccakCore<D>>(private val markByte: Byte = 0x01) : DigestEngine<D>() {
    private lateinit var a: LongArray
    private lateinit var tmpOut: ByteArray

    override fun engineReset() {
        doReset()
    }

    @Suppress("LongMethod")
    override fun processBlock(data: ByteArray) {
        /* Input block */
        var i = 0
        while (i < data.size) {
            a[i ushr 3] = a[i ushr 3] xor decodeLELong(data, i)
            i += 8
        }
        var t0: Long
        var t1: Long
        var t2: Long
        var t3: Long
        var t4: Long
        var tt0: Long
        var tt1: Long
        var tt2: Long
        var tt3: Long
        var t: Long
        var kt: Long
        var c0: Long
        var c1: Long
        var c2: Long
        var c3: Long
        var c4: Long
        var bnn: Long

        /*
		 * Unrolling four rounds kills performance big time
		 * on Intel x86 Core2, in both 32-bit and 64-bit modes
		 * (less than 1 MB/s instead of 55 MB/s on x86-64).
		 * Unrolling two rounds appears to be fine.
		 */
        var j = 0
        while (j < 24) {
            tt0 = a[1] xor a[6]
            tt1 = a[11] xor a[16]
            tt0 = tt0 xor (a[21] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[4] xor a[9]
            tt3 = a[14] xor a[19]
            tt0 = tt0 xor a[24]
            tt2 = tt2 xor tt3
            t0 = tt0 xor tt2
            tt0 = a[2] xor a[7]
            tt1 = a[12] xor a[17]
            tt0 = tt0 xor (a[22] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[0] xor a[5]
            tt3 = a[10] xor a[15]
            tt0 = tt0 xor a[20]
            tt2 = tt2 xor tt3
            t1 = tt0 xor tt2
            tt0 = a[3] xor a[8]
            tt1 = a[13] xor a[18]
            tt0 = tt0 xor (a[23] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[1] xor a[6]
            tt3 = a[11] xor a[16]
            tt0 = tt0 xor a[21]
            tt2 = tt2 xor tt3
            t2 = tt0 xor tt2
            tt0 = a[4] xor a[9]
            tt1 = a[14] xor a[19]
            tt0 = tt0 xor (a[24] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[2] xor a[7]
            tt3 = a[12] xor a[17]
            tt0 = tt0 xor a[22]
            tt2 = tt2 xor tt3
            t3 = tt0 xor tt2
            tt0 = a[0] xor a[5]
            tt1 = a[10] xor a[15]
            tt0 = tt0 xor (a[20] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[3] xor a[8]
            tt3 = a[13] xor a[18]
            tt0 = tt0 xor a[23]
            tt2 = tt2 xor tt3
            t4 = tt0 xor tt2
            a[0] = a[0] xor t0
            a[5] = a[5] xor t0
            a[10] = a[10] xor t0
            a[15] = a[15] xor t0
            a[20] = a[20] xor t0
            a[1] = a[1] xor t1
            a[6] = a[6] xor t1
            a[11] = a[11] xor t1
            a[16] = a[16] xor t1
            a[21] = a[21] xor t1
            a[2] = a[2] xor t2
            a[7] = a[7] xor t2
            a[12] = a[12] xor t2
            a[17] = a[17] xor t2
            a[22] = a[22] xor t2
            a[3] = a[3] xor t3
            a[8] = a[8] xor t3
            a[13] = a[13] xor t3
            a[18] = a[18] xor t3
            a[23] = a[23] xor t3
            a[4] = a[4] xor t4
            a[9] = a[9] xor t4
            a[14] = a[14] xor t4
            a[19] = a[19] xor t4
            a[24] = a[24] xor t4
            a[5] = a[5] shl 36 or (a[5] ushr 64 - 36)
            a[10] = a[10] shl 3 or (a[10] ushr 64 - 3)
            a[15] = a[15] shl 41 or (a[15] ushr 64 - 41)
            a[20] = a[20] shl 18 or (a[20] ushr 64 - 18)
            a[1] = a[1] shl 1 or (a[1] ushr 64 - 1)
            a[6] = a[6] shl 44 or (a[6] ushr 64 - 44)
            a[11] = a[11] shl 10 or (a[11] ushr 64 - 10)
            a[16] = a[16] shl 45 or (a[16] ushr 64 - 45)
            a[21] = a[21] shl 2 or (a[21] ushr 64 - 2)
            a[2] = a[2] shl 62 or (a[2] ushr 64 - 62)
            a[7] = a[7] shl 6 or (a[7] ushr 64 - 6)
            a[12] = a[12] shl 43 or (a[12] ushr 64 - 43)
            a[17] = a[17] shl 15 or (a[17] ushr 64 - 15)
            a[22] = a[22] shl 61 or (a[22] ushr 64 - 61)
            a[3] = a[3] shl 28 or (a[3] ushr 64 - 28)
            a[8] = a[8] shl 55 or (a[8] ushr 64 - 55)
            a[13] = a[13] shl 25 or (a[13] ushr 64 - 25)
            a[18] = a[18] shl 21 or (a[18] ushr 64 - 21)
            a[23] = a[23] shl 56 or (a[23] ushr 64 - 56)
            a[4] = a[4] shl 27 or (a[4] ushr 64 - 27)
            a[9] = a[9] shl 20 or (a[9] ushr 64 - 20)
            a[14] = a[14] shl 39 or (a[14] ushr 64 - 39)
            a[19] = a[19] shl 8 or (a[19] ushr 64 - 8)
            a[24] = a[24] shl 14 or (a[24] ushr 64 - 14)
            bnn = a[12].inv()
            kt = a[6] or a[12]
            c0 = a[0] xor kt
            kt = bnn or a[18]
            c1 = a[6] xor kt
            kt = a[18] and a[24]
            c2 = a[12] xor kt
            kt = a[24] or a[0]
            c3 = a[18] xor kt
            kt = a[0] and a[6]
            c4 = a[24] xor kt
            a[0] = c0
            a[6] = c1
            a[12] = c2
            a[18] = c3
            a[24] = c4
            bnn = a[22].inv()
            kt = a[9] or a[10]
            c0 = a[3] xor kt
            kt = a[10] and a[16]
            c1 = a[9] xor kt
            kt = a[16] or bnn
            c2 = a[10] xor kt
            kt = a[22] or a[3]
            c3 = a[16] xor kt
            kt = a[3] and a[9]
            c4 = a[22] xor kt
            a[3] = c0
            a[9] = c1
            a[10] = c2
            a[16] = c3
            a[22] = c4
            bnn = a[19].inv()
            kt = a[7] or a[13]
            c0 = a[1] xor kt
            kt = a[13] and a[19]
            c1 = a[7] xor kt
            kt = bnn and a[20]
            c2 = a[13] xor kt
            kt = a[20] or a[1]
            c3 = bnn xor kt
            kt = a[1] and a[7]
            c4 = a[20] xor kt
            a[1] = c0
            a[7] = c1
            a[13] = c2
            a[19] = c3
            a[20] = c4
            bnn = a[17].inv()
            kt = a[5] and a[11]
            c0 = a[4] xor kt
            kt = a[11] or a[17]
            c1 = a[5] xor kt
            kt = bnn or a[23]
            c2 = a[11] xor kt
            kt = a[23] and a[4]
            c3 = bnn xor kt
            kt = a[4] or a[5]
            c4 = a[23] xor kt
            a[4] = c0
            a[5] = c1
            a[11] = c2
            a[17] = c3
            a[23] = c4
            bnn = a[8].inv()
            kt = bnn and a[14]
            c0 = a[2] xor kt
            kt = a[14] or a[15]
            c1 = bnn xor kt
            kt = a[15] and a[21]
            c2 = a[14] xor kt
            kt = a[21] or a[2]
            c3 = a[15] xor kt
            kt = a[2] and a[8]
            c4 = a[21] xor kt
            a[2] = c0
            a[8] = c1
            a[14] = c2
            a[15] = c3
            a[21] = c4
            a[0] = a[0] xor RC[j + 0]
            tt0 = a[6] xor a[9]
            tt1 = a[7] xor a[5]
            tt0 = tt0 xor (a[8] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[24] xor a[22]
            tt3 = a[20] xor a[23]
            tt0 = tt0 xor a[21]
            tt2 = tt2 xor tt3
            t0 = tt0 xor tt2
            tt0 = a[12] xor a[10]
            tt1 = a[13] xor a[11]
            tt0 = tt0 xor (a[14] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[0] xor a[3]
            tt3 = a[1] xor a[4]
            tt0 = tt0 xor a[2]
            tt2 = tt2 xor tt3
            t1 = tt0 xor tt2
            tt0 = a[18] xor a[16]
            tt1 = a[19] xor a[17]
            tt0 = tt0 xor (a[15] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[6] xor a[9]
            tt3 = a[7] xor a[5]
            tt0 = tt0 xor a[8]
            tt2 = tt2 xor tt3
            t2 = tt0 xor tt2
            tt0 = a[24] xor a[22]
            tt1 = a[20] xor a[23]
            tt0 = tt0 xor (a[21] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[12] xor a[10]
            tt3 = a[13] xor a[11]
            tt0 = tt0 xor a[14]
            tt2 = tt2 xor tt3
            t3 = tt0 xor tt2
            tt0 = a[0] xor a[3]
            tt1 = a[1] xor a[4]
            tt0 = tt0 xor (a[2] xor tt1)
            tt0 = tt0 shl 1 or (tt0 ushr 63)
            tt2 = a[18] xor a[16]
            tt3 = a[19] xor a[17]
            tt0 = tt0 xor a[15]
            tt2 = tt2 xor tt3
            t4 = tt0 xor tt2
            a[0] = a[0] xor t0
            a[3] = a[3] xor t0
            a[1] = a[1] xor t0
            a[4] = a[4] xor t0
            a[2] = a[2] xor t0
            a[6] = a[6] xor t1
            a[9] = a[9] xor t1
            a[7] = a[7] xor t1
            a[5] = a[5] xor t1
            a[8] = a[8] xor t1
            a[12] = a[12] xor t2
            a[10] = a[10] xor t2
            a[13] = a[13] xor t2
            a[11] = a[11] xor t2
            a[14] = a[14] xor t2
            a[18] = a[18] xor t3
            a[16] = a[16] xor t3
            a[19] = a[19] xor t3
            a[17] = a[17] xor t3
            a[15] = a[15] xor t3
            a[24] = a[24] xor t4
            a[22] = a[22] xor t4
            a[20] = a[20] xor t4
            a[23] = a[23] xor t4
            a[21] = a[21] xor t4
            a[3] = a[3] shl 36 or (a[3] ushr 64 - 36)
            a[1] = a[1] shl 3 or (a[1] ushr 64 - 3)
            a[4] = a[4] shl 41 or (a[4] ushr 64 - 41)
            a[2] = a[2] shl 18 or (a[2] ushr 64 - 18)
            a[6] = a[6] shl 1 or (a[6] ushr 64 - 1)
            a[9] = a[9] shl 44 or (a[9] ushr 64 - 44)
            a[7] = a[7] shl 10 or (a[7] ushr 64 - 10)
            a[5] = a[5] shl 45 or (a[5] ushr 64 - 45)
            a[8] = a[8] shl 2 or (a[8] ushr 64 - 2)
            a[12] = a[12] shl 62 or (a[12] ushr 64 - 62)
            a[10] = a[10] shl 6 or (a[10] ushr 64 - 6)
            a[13] = a[13] shl 43 or (a[13] ushr 64 - 43)
            a[11] = a[11] shl 15 or (a[11] ushr 64 - 15)
            a[14] = a[14] shl 61 or (a[14] ushr 64 - 61)
            a[18] = a[18] shl 28 or (a[18] ushr 64 - 28)
            a[16] = a[16] shl 55 or (a[16] ushr 64 - 55)
            a[19] = a[19] shl 25 or (a[19] ushr 64 - 25)
            a[17] = a[17] shl 21 or (a[17] ushr 64 - 21)
            a[15] = a[15] shl 56 or (a[15] ushr 64 - 56)
            a[24] = a[24] shl 27 or (a[24] ushr 64 - 27)
            a[22] = a[22] shl 20 or (a[22] ushr 64 - 20)
            a[20] = a[20] shl 39 or (a[20] ushr 64 - 39)
            a[23] = a[23] shl 8 or (a[23] ushr 64 - 8)
            a[21] = a[21] shl 14 or (a[21] ushr 64 - 14)
            bnn = a[13].inv()
            kt = a[9] or a[13]
            c0 = a[0] xor kt
            kt = bnn or a[17]
            c1 = a[9] xor kt
            kt = a[17] and a[21]
            c2 = a[13] xor kt
            kt = a[21] or a[0]
            c3 = a[17] xor kt
            kt = a[0] and a[9]
            c4 = a[21] xor kt
            a[0] = c0
            a[9] = c1
            a[13] = c2
            a[17] = c3
            a[21] = c4
            bnn = a[14].inv()
            kt = a[22] or a[1]
            c0 = a[18] xor kt
            kt = a[1] and a[5]
            c1 = a[22] xor kt
            kt = a[5] or bnn
            c2 = a[1] xor kt
            kt = a[14] or a[18]
            c3 = a[5] xor kt
            kt = a[18] and a[22]
            c4 = a[14] xor kt
            a[18] = c0
            a[22] = c1
            a[1] = c2
            a[5] = c3
            a[14] = c4
            bnn = a[23].inv()
            kt = a[10] or a[19]
            c0 = a[6] xor kt
            kt = a[19] and a[23]
            c1 = a[10] xor kt
            kt = bnn and a[2]
            c2 = a[19] xor kt
            kt = a[2] or a[6]
            c3 = bnn xor kt
            kt = a[6] and a[10]
            c4 = a[2] xor kt
            a[6] = c0
            a[10] = c1
            a[19] = c2
            a[23] = c3
            a[2] = c4
            bnn = a[11].inv()
            kt = a[3] and a[7]
            c0 = a[24] xor kt
            kt = a[7] or a[11]
            c1 = a[3] xor kt
            kt = bnn or a[15]
            c2 = a[7] xor kt
            kt = a[15] and a[24]
            c3 = bnn xor kt
            kt = a[24] or a[3]
            c4 = a[15] xor kt
            a[24] = c0
            a[3] = c1
            a[7] = c2
            a[11] = c3
            a[15] = c4
            bnn = a[16].inv()
            kt = bnn and a[20]
            c0 = a[12] xor kt
            kt = a[20] or a[4]
            c1 = bnn xor kt
            kt = a[4] and a[8]
            c2 = a[20] xor kt
            kt = a[8] or a[12]
            c3 = a[4] xor kt
            kt = a[12] and a[16]
            c4 = a[8] xor kt
            a[12] = c0
            a[16] = c1
            a[20] = c2
            a[4] = c3
            a[8] = c4
            a[0] = a[0] xor RC[j + 1]
            t = a[5]
            a[5] = a[18]
            a[18] = a[11]
            a[11] = a[10]
            a[10] = a[6]
            a[6] = a[22]
            a[22] = a[20]
            a[20] = a[12]
            a[12] = a[19]
            a[19] = a[15]
            a[15] = a[24]
            a[24] = a[8]
            a[8] = t
            t = a[1]
            a[1] = a[9]
            a[9] = a[14]
            a[14] = a[2]
            a[2] = a[13]
            a[13] = a[23]
            a[23] = a[4]
            a[4] = a[21]
            a[21] = a[16]
            a[16] = a[3]
            a[3] = a[17]
            a[17] = a[7]
            a[7] = t
            j += 2
        }
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        val buf = blockBuffer
        if (ptr + 1 == buf.size) {
            buf[ptr] = (markByte + 0x80).toByte()
        } else {
            buf[ptr] = markByte
            for (i in ptr + 1 until buf.size - 1) buf[i] = 0
            buf[buf.size - 1] = 0x80.toByte()
        }
        processBlock(buf)
        a[1] = a[1].inv()
        a[2] = a[2].inv()
        a[8] = a[8].inv()
        a[12] = a[12].inv()
        a[17] = a[17].inv()
        a[20] = a[20].inv()
        val dlen = digestLength
        var i = 0
        while (i < dlen) {
            encodeLELong(a[i ushr 3], tmpOut, i)
            i += 8
        }
        tmpOut.copyInto(output, outputOffset, 0, dlen)
    }

    override fun doInit() {
        a = LongArray(25)
        tmpOut = ByteArray(digestLength + 7 and 7.inv())
        doReset()
    }

    override val blockLength: Int
        get() = 200 - 2 * digestLength

    private fun doReset() {
        for (i in 0..24) a[i] = 0
        a[1] = -0x1L
        a[2] = -0x1L
        a[8] = -0x1L
        a[12] = -0x1L
        a[17] = -0x1L
        a[20] = -0x1L
    }

    override fun copyState(dest: D): D {
        a.copyInto(dest.a, 0, 0, 25)
        return super.copyState(dest)
    }

    companion object {
        private val RC = longArrayOf(
            0x0000000000000001L, 0x0000000000008082L,
            -0x7fffffffffff7f76L, -0x7fffffff7fff8000L,
            0x000000000000808BL, 0x0000000080000001L,
            -0x7fffffff7fff7f7fL, -0x7fffffffffff7ff7L,
            0x000000000000008AL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, -0x7fffffffffffff75L,
            -0x7fffffffffff7f77L, -0x7fffffffffff7ffdL,
            -0x7fffffffffff7ffeL, -0x7fffffffffffff80L,
            0x000000000000800AL, -0x7fffffff7ffffff6L,
            -0x7fffffff7fff7f7fL, -0x7fffffffffff7f80L,
            0x0000000080000001L, -0x7fffffff7fff7ff8L
        )
    }
}
