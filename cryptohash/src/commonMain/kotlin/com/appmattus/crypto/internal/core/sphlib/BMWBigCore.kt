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

import com.appmattus.crypto.internal.core.circularLeftLong
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * This class implements BMW-384 and BMW-512.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class BMWBigCore<D : BMWBigCore<D>> : DigestEngine<D>() {

    private lateinit var m: LongArray
    private lateinit var h: LongArray
    private lateinit var h2: LongArray
    private lateinit var q: LongArray
    private lateinit var w: LongArray

    override fun copyState(dest: D): D {
        h.copyInto(dest.h, 0, 0, h.size)
        return super.copyState(dest)
    }

    override fun engineReset() {
        val iv = initVal
        iv.copyInto(h, 0, 0, iv.size)
    }

    protected abstract val initVal: LongArray

    @Suppress("LongMethod")
    private fun compress(m: LongArray) {
        val h = h
        val q = q
        val w = w
        w[0] = ((m[5] xor h[5]) - (m[7] xor h[7]) + (m[10] xor h[10]) + (m[13] xor h[13]) + (m[14] xor h[14]))
        w[1] = ((m[6] xor h[6]) - (m[8] xor h[8]) + (m[11] xor h[11]) + (m[14] xor h[14])) - (m[15] xor h[15])
        w[2] = (m[0] xor h[0]) + (m[7] xor h[7]) + (m[9] xor h[9]) - (m[12] xor h[12]) + (m[15] xor h[15])
        w[3] = (m[0] xor h[0]) - (m[1] xor h[1]) + (m[8] xor h[8]) - (m[10] xor h[10]) + (m[13] xor h[13])
        w[4] = (m[1] xor h[1]) + (m[2] xor h[2]) + (m[9] xor h[9]) - (m[11] xor h[11]) - (m[14] xor h[14])
        w[5] = (m[3] xor h[3]) - (m[2] xor h[2]) + (m[10] xor h[10]) - (m[12] xor h[12]) + (m[15] xor h[15])
        w[6] = ((m[4] xor h[4]) - (m[0] xor h[0]) - (m[3] xor h[3]) - (m[11] xor h[11])) + (m[13] xor h[13])
        w[7] = ((m[1] xor h[1]) - (m[4] xor h[4]) - (m[5] xor h[5]) - (m[12] xor h[12]) - (m[14] xor h[14]))
        w[8] = (m[2] xor h[2]) - (m[5] xor h[5]) - (m[6] xor h[6]) + (m[13] xor h[13]) - (m[15] xor h[15])
        w[9] = (m[0] xor h[0]) - (m[3] xor h[3]) + (m[6] xor h[6]) - (m[7] xor h[7]) + (m[14] xor h[14])
        w[10] = ((m[8] xor h[8]) - (m[1] xor h[1]) - (m[4] xor h[4]) - (m[7] xor h[7])) + (m[15] xor h[15])
        w[11] = ((m[8] xor h[8]) - (m[0] xor h[0]) - (m[2] xor h[2]) - (m[5] xor h[5])) + (m[9] xor h[9])
        w[12] = ((m[1] xor h[1]) + (m[3] xor h[3]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[10] xor h[10])
        w[13] = ((m[2] xor h[2]) + (m[4] xor h[4]) + (m[7] xor h[7]) + (m[10] xor h[10]) + (m[11] xor h[11]))
        w[14] = (m[3] xor h[3]) - (m[5] xor h[5]) + (m[8] xor h[8]) - (m[11] xor h[11]) - (m[12] xor h[12])
        w[15] = ((m[12] xor h[12]) - (m[4] xor h[4]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[13] xor h[13])
        run {
            var u = 0
            while (u < 15) {
                q[u + 0] = ((w[u + 0] ushr 1) xor (w[u + 0] shl 3)
                        xor circularLeftLong(w[u + 0], 4)
                        xor circularLeftLong(w[u + 0], 37)) + h[u + 1]
                q[u + 1] = ((w[u + 1] ushr 1) xor (w[u + 1] shl 2)
                        xor circularLeftLong(w[u + 1], 13)
                        xor circularLeftLong(w[u + 1], 43)) + h[u + 2]
                q[u + 2] = ((w[u + 2] ushr 2) xor (w[u + 2] shl 1)
                        xor circularLeftLong(w[u + 2], 19)
                        xor circularLeftLong(w[u + 2], 53)) + h[u + 3]
                q[u + 3] = ((w[u + 3] ushr 2) xor (w[u + 3] shl 2)
                        xor circularLeftLong(w[u + 3], 28)
                        xor circularLeftLong(w[u + 3], 59)) + h[u + 4]
                q[u + 4] = ((w[u + 4] ushr 1) xor w[u + 4]) + h[u + 5]
                u += 5
            }
        }
        q[15] = (((w[15] ushr 1) xor (w[15] shl 3)
                xor circularLeftLong(w[15], 4) xor circularLeftLong(w[15], 37)) +
                h[0])
        for (u in 16..17) {
            q[u] = (((q[u - 16] ushr 1) xor (q[u - 16] shl 2)
                    xor circularLeftLong(q[u - 16], 13)
                    xor circularLeftLong(q[u - 16], 43)) +
                    ((q[u - 15] ushr 2) xor (q[u - 15] shl 1)
                            xor circularLeftLong(q[u - 15], 19)
                            xor circularLeftLong(q[u - 15], 53)) +
                    ((q[u - 14] ushr 2) xor (q[u - 14] shl 2)
                            xor circularLeftLong(q[u - 14], 28)
                            xor circularLeftLong(q[u - 14], 59)) +
                    ((q[u - 13] ushr 1) xor (q[u - 13] shl 3)
                            xor circularLeftLong(q[u - 13], 4)
                            xor circularLeftLong(q[u - 13], 37)) +
                    ((q[u - 12] ushr 1) xor (q[u - 12] shl 2)
                            xor circularLeftLong(q[u - 12], 13)
                            xor circularLeftLong(q[u - 12], 43)) +
                    ((q[u - 11] ushr 2) xor (q[u - 11] shl 1)
                            xor circularLeftLong(q[u - 11], 19)
                            xor circularLeftLong(q[u - 11], 53)) +
                    ((q[u - 10] ushr 2) xor (q[u - 10] shl 2)
                            xor circularLeftLong(q[u - 10], 28)
                            xor circularLeftLong(q[u - 10], 59)) +
                    ((q[u - 9] ushr 1) xor (q[u - 9] shl 3)
                            xor circularLeftLong(q[u - 9], 4)
                            xor circularLeftLong(q[u - 9], 37)) +
                    ((q[u - 8] ushr 1) xor (q[u - 8] shl 2)
                            xor circularLeftLong(q[u - 8], 13)
                            xor circularLeftLong(q[u - 8], 43)) +
                    ((q[u - 7] ushr 2) xor (q[u - 7] shl 1)
                            xor circularLeftLong(q[u - 7], 19)
                            xor circularLeftLong(q[u - 7], 53)) +
                    ((q[u - 6] ushr 2) xor (q[u - 6] shl 2)
                            xor circularLeftLong(q[u - 6], 28)
                            xor circularLeftLong(q[u - 6], 59)) +
                    ((q[u - 5] ushr 1) xor (q[u - 5] shl 3)
                            xor circularLeftLong(q[u - 5], 4)
                            xor circularLeftLong(q[u - 5], 37)) +
                    ((q[u - 4] ushr 1) xor (q[u - 4] shl 2)
                            xor circularLeftLong(q[u - 4], 13)
                            xor circularLeftLong(q[u - 4], 43)) +
                    ((q[u - 3] ushr 2) xor (q[u - 3] shl 1)
                            xor circularLeftLong(q[u - 3], 19)
                            xor circularLeftLong(q[u - 3], 53)) +
                    ((q[u - 2] ushr 2) xor (q[u - 2] shl 2)
                            xor circularLeftLong(q[u - 2], 28)
                            xor circularLeftLong(q[u - 2], 59)) +
                    ((q[u - 1] ushr 1) xor (q[u - 1] shl 3)
                            xor circularLeftLong(q[u - 1], 4)
                            xor circularLeftLong(q[u - 1], 37)) +
                    ((circularLeftLong(
                        m[u - 16 + 0 and 15],
                        (u - 16 + 0 and 15) + 1
                    ) +
                            circularLeftLong(
                                m[u - 16 + 3 and 15],
                                (u - 16 + 3 and 15) + 1
                            ) -
                            circularLeftLong(
                                m[u - 16 + 10 and 15],
                                (u - 16 + 10 and 15) + 1
                            ) +
                            K[u - 16]) xor h[u - 16 + 7 and 15]))
        }
        for (u in 18..31) {
            q[u] = (q[u - 16] + circularLeftLong(q[u - 15], 5) +
                    q[u - 14] + circularLeftLong(q[u - 13], 11) +
                    q[u - 12] + circularLeftLong(q[u - 11], 27) +
                    q[u - 10] + circularLeftLong(q[u - 9], 32) +
                    q[u - 8] + circularLeftLong(q[u - 7], 37) +
                    q[u - 6] + circularLeftLong(q[u - 5], 43) +
                    q[u - 4] + circularLeftLong(q[u - 3], 53) +
                    ((q[u - 2] ushr 1) xor q[u - 2]) +
                    ((q[u - 1] ushr 2) xor q[u - 1]) +
                    ((circularLeftLong(
                        m[u - 16 + 0 and 15],
                        (u - 16 + 0 and 15) + 1
                    ) +
                            circularLeftLong(
                                m[u - 16 + 3 and 15],
                                (u - 16 + 3 and 15) + 1
                            ) -
                            circularLeftLong(
                                m[u - 16 + 10 and 15],
                                (u - 16 + 10 and 15) + 1
                            ) +
                            K[u - 16]) xor h[u - 16 + 7 and 15]))
        }
        val xl = (q[16] xor q[17] xor q[18] xor q[19]
                xor q[20] xor q[21] xor q[22] xor q[23])
        val xh = (xl xor q[24] xor q[25] xor q[26] xor q[27]
                xor q[28] xor q[29] xor q[30] xor q[31])
        h[0] = ((xh shl 5) xor (q[16] ushr 5) xor m[0]) + (xl xor q[24] xor q[0])
        h[1] = ((xh ushr 7) xor (q[17] shl 8) xor m[1]) + (xl xor q[25] xor q[1])
        h[2] = ((xh ushr 5) xor (q[18] shl 5) xor m[2]) + (xl xor q[26] xor q[2])
        h[3] = ((xh ushr 1) xor (q[19] shl 5) xor m[3]) + (xl xor q[27] xor q[3])
        h[4] = ((xh ushr 3) xor (q[20] shl 0) xor m[4]) + (xl xor q[28] xor q[4])
        h[5] = ((xh shl 6) xor (q[21] ushr 6) xor m[5]) + (xl xor q[29] xor q[5])
        h[6] = ((xh ushr 4) xor (q[22] shl 6) xor m[6]) + (xl xor q[30] xor q[6])
        h[7] = (((xh ushr 11) xor (q[23] shl 2) xor m[7]) +
                (xl xor q[31] xor q[7]))
        h[8] = (circularLeftLong(h[4], 9) + (xh xor q[24] xor m[8]) +
                ((xl shl 8) xor q[23] xor q[8]))
        h[9] = (circularLeftLong(h[5], 10) + (xh xor q[25] xor m[9]) +
                ((xl ushr 6) xor q[16] xor q[9]))
        h[10] = (circularLeftLong(h[6], 11) + (xh xor q[26] xor m[10]) +
                ((xl shl 6) xor q[17] xor q[10]))
        h[11] = (circularLeftLong(h[7], 12) + (xh xor q[27] xor m[11]) +
                ((xl shl 4) xor q[18] xor q[11]))
        h[12] = (circularLeftLong(h[0], 13) + (xh xor q[28] xor m[12]) +
                ((xl ushr 3) xor q[19] xor q[12]))
        h[13] = (circularLeftLong(h[1], 14) + (xh xor q[29] xor m[13]) +
                ((xl ushr 4) xor q[20] xor q[13]))
        h[14] = (circularLeftLong(h[2], 15) + (xh xor q[30] xor m[14]) +
                ((xl ushr 7) xor q[21] xor q[14]))
        h[15] = (circularLeftLong(h[3], 16) + (xh xor q[31] xor m[15]) +
                ((xl ushr 2) xor q[22] xor q[15]))
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val buf = blockBuffer
        var ptr = flush()
        val bitLen = (blockCount shl 10) + (ptr shl 3)
        buf[ptr++] = 0x80.toByte()
        if (ptr > 120) {
            for (i in ptr..127) buf[i] = 0
            processBlock(buf)
            ptr = 0
        }
        for (i in ptr..119) buf[i] = 0
        encodeLELong(bitLen, buf, 120)
        processBlock(buf)
        val tmp = h
        h = h2
        h2 = tmp
        FINAL.copyInto(h, 0, 0, 16)
        compress(h2)
        val outLen = digestLength ushr 3
        var i = 0
        var j = 16 - outLen
        while (i < outLen) {
            encodeLELong(h[j], output, outputOffset + 8 * i)
            i++
            j++
        }
    }

    override fun doInit() {
        m = LongArray(16)
        h = LongArray(16)
        h2 = LongArray(16)
        w = LongArray(16)
        q = LongArray(32)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        for (i in 0..15) m[i] = decodeLELong(data, i * 8)
        compress(m)
    }

    companion object {
        private val FINAL = longArrayOf(
            -0x5555555555555560L, -0x555555555555555fL,
            -0x555555555555555eL, -0x555555555555555dL,
            -0x555555555555555cL, -0x555555555555555bL,
            -0x555555555555555aL, -0x5555555555555559L,
            -0x5555555555555558L, -0x5555555555555557L,
            -0x5555555555555556L, -0x5555555555555555L,
            -0x5555555555555554L, -0x5555555555555553L,
            -0x5555555555555552L, -0x5555555555555551L
        )

        @Suppress("INTEGER_OVERFLOW")
        private val K = longArrayOf(
            16L * 0x0555555555555555L, 17L * 0x0555555555555555L,
            18L * 0x0555555555555555L, 19L * 0x0555555555555555L,
            20L * 0x0555555555555555L, 21L * 0x0555555555555555L,
            22L * 0x0555555555555555L, 23L * 0x0555555555555555L,
            24L * 0x0555555555555555L, 25L * 0x0555555555555555L,
            26L * 0x0555555555555555L, 27L * 0x0555555555555555L,
            28L * 0x0555555555555555L, 29L * 0x0555555555555555L,
            30L * 0x0555555555555555L, 31L * 0x0555555555555555L
        )
    }
}
