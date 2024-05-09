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

import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 * This class implements BMW-224 and BMW-256.
 *
 * @version $Revision: 214 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal abstract class BMWSmallCore<D : BMWSmallCore<D>> : DigestEngine<D>() {

    private lateinit var m: IntArray
    private lateinit var h: IntArray
    private lateinit var h2: IntArray
    private lateinit var q: IntArray

    override fun copyState(dest: D): D {
        h.copyInto(dest.h, 0, 0, h.size)
        return super.copyState(dest)
    }

    override fun engineReset() {
        val iv = initVal
        iv.copyInto(h, 0, 0, iv.size)
    }

    protected abstract val initVal: IntArray

    @Suppress("INTEGER_OVERFLOW", "LongMethod", "Wrapping")
    private fun compress(m: IntArray) {
        val h = h
        val q = q
        q[0] = (((m[5] xor h[5]) - (m[7] xor h[7]) + (m[10] xor h[10]) +
                (m[13] xor h[13]) + (m[14] xor h[14])) ushr 1
                xor (((m[5] xor h[5]) - (m[7] xor h[7]) + (m[10] xor h[10]) +
                (m[13] xor h[13]) + (m[14] xor h[14])) shl 3)
                xor ((m[5] xor h[5]) - (m[7] xor h[7]) + (m[10] xor h[10]) + (m[13] xor h[13]) + (m[14] xor h[14])).rotateLeft(4)
                xor ((m[5] xor h[5]) - (m[7] xor h[7]) + (m[10] xor h[10]) + (m[13] xor h[13]) + (m[14] xor h[14])).rotateLeft(19)) +
                h[1]
        q[1] = (((m[6] xor h[6]) - (m[8] xor h[8]) + (m[11] xor h[11]) +
                (m[14] xor h[14])) - (m[15] xor h[15]) ushr 1
                xor (((m[6] xor h[6]) - (m[8] xor h[8]) + (m[11] xor h[11]) +
                (m[14] xor h[14])) - (m[15] xor h[15]) shl 2)
                xor ((m[6] xor h[6]) - (m[8] xor h[8]) + (m[11] xor h[11]) + (m[14] xor h[14]) - (m[15] xor h[15])).rotateLeft(8)
                xor ((m[6] xor h[6]) - (m[8] xor h[8]) + (m[11] xor h[11]) + (m[14] xor h[14]) - (m[15] xor h[15])).rotateLeft(23)) +
                h[2]
        q[2] = (((m[0] xor h[0]) + (m[7] xor h[7]) + (m[9] xor h[9]) -
                (m[12] xor h[12]) + (m[15] xor h[15])) ushr 2
                xor (((m[0] xor h[0]) + (m[7] xor h[7]) + (m[9] xor h[9]) -
                (m[12] xor h[12]) + (m[15] xor h[15])) shl 1)
                xor (((m[0] xor h[0]) + (m[7] xor h[7]) + (m[9] xor h[9])) - (m[12] xor h[12]) + (m[15] xor h[15])).rotateLeft(12)
                xor (((m[0] xor h[0]) + (m[7] xor h[7]) + (m[9] xor h[9])) - (m[12] xor h[12]) + (m[15] xor h[15])).rotateLeft(25)) +
                h[3]
        q[3] = (((m[0] xor h[0]) - (m[1] xor h[1]) + (m[8] xor h[8]) -
                (m[10] xor h[10]) + (m[13] xor h[13])) ushr 2
                xor (((m[0] xor h[0]) - (m[1] xor h[1]) + (m[8] xor h[8]) -
                (m[10] xor h[10]) + (m[13] xor h[13])) shl 2)
                xor ((m[0] xor h[0]) - (m[1] xor h[1]) + (m[8] xor h[8]) - (m[10] xor h[10]) + (m[13] xor h[13])).rotateLeft(15)
                xor ((m[0] xor h[0]) - (m[1] xor h[1]) + (m[8] xor h[8]) - (m[10] xor h[10]) + (m[13] xor h[13])).rotateLeft(29)) +
                h[4]
        q[4] = ((m[1] xor h[1]) + (m[2] xor h[2]) + (m[9] xor h[9]) - (m[11] xor h[11]) - (m[14] xor h[14]) ushr 1
                xor (m[1] xor h[1]) + (m[2] xor h[2]) + (m[9] xor h[9]) - (m[11] xor h[11]) - (m[14] xor h[14])) + h[5]
        q[5] = (((m[3] xor h[3]) - (m[2] xor h[2]) + (m[10] xor h[10]) -
                (m[12] xor h[12]) + (m[15] xor h[15])) ushr 1
                xor (((m[3] xor h[3]) - (m[2] xor h[2]) + (m[10] xor h[10]) -
                (m[12] xor h[12]) + (m[15] xor h[15])) shl 3)
                xor ((m[3] xor h[3]) - (m[2] xor h[2]) + (m[10] xor h[10]) - (m[12] xor h[12]) + (m[15] xor h[15])).rotateLeft(4)
                xor ((m[3] xor h[3]) - (m[2] xor h[2]) + (m[10] xor h[10]) - (m[12] xor h[12]) + (m[15] xor h[15])).rotateLeft(19)) +
                h[6]
        q[6] = (((m[4] xor h[4]) - (m[0] xor h[0]) - (m[3] xor h[3]) -
                (m[11] xor h[11])) + (m[13] xor h[13]) ushr 1
                xor (((m[4] xor h[4]) - (m[0] xor h[0]) - (m[3] xor h[3]) -
                (m[11] xor h[11])) + (m[13] xor h[13]) shl 2)
                xor (((m[4] xor h[4]) - (m[0] xor h[0]) - (m[3] xor h[3]) - (m[11] xor h[11])) + (m[13] xor h[13])).rotateLeft(8)
                xor (((m[4] xor h[4]) - (m[0] xor h[0]) - (m[3] xor h[3]) - (m[11] xor h[11])) + (m[13] xor h[13])).rotateLeft(23)) +
                h[7]
        q[7] = (((m[1] xor h[1]) - (m[4] xor h[4]) - (m[5] xor h[5]) -
                (m[12] xor h[12]) - (m[14] xor h[14])) ushr 2
                xor (((m[1] xor h[1]) - (m[4] xor h[4]) - (m[5] xor h[5]) -
                (m[12] xor h[12]) - (m[14] xor h[14])) shl 1)
                xor ((m[1] xor h[1]) - (m[4] xor h[4]) - (m[5] xor h[5]) - (m[12] xor h[12]) - (m[14] xor h[14])).rotateLeft(12)
                xor ((m[1] xor h[1]) - (m[4] xor h[4]) - (m[5] xor h[5]) - (m[12] xor h[12]) - (m[14] xor h[14])).rotateLeft(25)) +
                h[8]
        q[8] = (((m[2] xor h[2]) - (m[5] xor h[5]) - (m[6] xor h[6]) + (m[13] xor h[13]) - (m[15] xor h[15])) ushr 2 xor
                (((m[2] xor h[2]) - (m[5] xor h[5]) - (m[6] xor h[6]) + (m[13] xor h[13]) - (m[15] xor h[15])) shl 2) xor
                (((m[2] xor h[2]) - (m[5] xor h[5]) - (m[6] xor h[6])) + (m[13] xor h[13]) - (m[15] xor h[15])).rotateLeft(15) xor
                (((m[2] xor h[2]) - (m[5] xor h[5]) - (m[6] xor h[6])) + (m[13] xor h[13]) - (m[15] xor h[15])).rotateLeft(29)) +
                h[9]
        q[9] = (((m[0] xor h[0]) - (m[3] xor h[3]) + (m[6] xor h[6]) - (m[7] xor h[7]) + (m[14] xor h[14])) ushr 1 xor
                ((m[0] xor h[0]) - (m[3] xor h[3]) + (m[6] xor h[6]) - (m[7] xor h[7]) + (m[14] xor h[14]))) + h[10]
        q[10] = (((m[8] xor h[8]) - (m[1] xor h[1]) - (m[4] xor h[4]) - (m[7] xor h[7])) + (m[15] xor h[15]) ushr 1 xor
                (((m[8] xor h[8]) - (m[1] xor h[1]) - (m[4] xor h[4]) - (m[7] xor h[7])) + (m[15] xor h[15]) shl 3) xor
                (((m[8] xor h[8]) - (m[1] xor h[1]) - (m[4] xor h[4]) - (m[7] xor h[7])) + (m[15] xor h[15])).rotateLeft(4) xor
                (((m[8] xor h[8]) - (m[1] xor h[1]) - (m[4] xor h[4]) - (m[7] xor h[7])) + (m[15] xor h[15])).rotateLeft(19)) +
                h[11]
        q[11] = (((m[8] xor h[8]) - (m[0] xor h[0]) - (m[2] xor h[2]) - (m[5] xor h[5])) + (m[9] xor h[9]) ushr 1 xor
                (((m[8] xor h[8]) - (m[0] xor h[0]) - (m[2] xor h[2]) - (m[5] xor h[5])) + (m[9] xor h[9]) shl 2) xor
                (((m[8] xor h[8]) - (m[0] xor h[0]) - (m[2] xor h[2]) - (m[5] xor h[5])) + (m[9] xor h[9])).rotateLeft(8) xor
                (((m[8] xor h[8]) - (m[0] xor h[0]) - (m[2] xor h[2]) - (m[5] xor h[5])) + (m[9] xor h[9])).rotateLeft(23)) +
                h[12]
        q[12] = (((m[1] xor h[1]) + (m[3] xor h[3]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[10] xor h[10]) ushr 2 xor
                (((m[1] xor h[1]) + (m[3] xor h[3]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[10] xor h[10]) shl 1) xor
                ((m[1] xor h[1]) + (m[3] xor h[3]) - (m[6] xor h[6]) - (m[9] xor h[9]) + (m[10] xor h[10])).rotateLeft(12) xor
                ((m[1] xor h[1]) + (m[3] xor h[3]) - (m[6] xor h[6]) - (m[9] xor h[9]) + (m[10] xor h[10])).rotateLeft(25)) +
                h[13]
        q[13] = (((m[2] xor h[2]) + (m[4] xor h[4]) + (m[7] xor h[7]) + (m[10] xor h[10]) + (m[11] xor h[11])) ushr 2 xor
                (((m[2] xor h[2]) + (m[4] xor h[4]) + (m[7] xor h[7]) + (m[10] xor h[10]) + (m[11] xor h[11])) shl 2) xor
                ((m[2] xor h[2]) + (m[4] xor h[4]) + (m[7] xor h[7]) + (m[10] xor h[10]) + (m[11] xor h[11])).rotateLeft(15) xor
                ((m[2] xor h[2]) + (m[4] xor h[4]) + (m[7] xor h[7]) + (m[10] xor h[10]) + (m[11] xor h[11])).rotateLeft(29)) +
                h[14]
        q[14] = ((m[3] xor h[3]) - (m[5] xor h[5]) + (m[8] xor h[8]) - (m[11] xor h[11]) - (m[12] xor h[12]) ushr 1 xor
                (m[3] xor h[3]) - (m[5] xor h[5]) + (m[8] xor h[8]) - (m[11] xor h[11]) - (m[12] xor h[12])) + h[15]
        q[15] = (((m[12] xor h[12]) - (m[4] xor h[4]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[13] xor h[13]) ushr 1 xor
                (((m[12] xor h[12]) - (m[4] xor h[4]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[13] xor h[13]) shl 3) xor
                (((m[12] xor h[12]) - (m[4] xor h[4]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[13] xor h[13])).rotateLeft(4) xor
                (((m[12] xor h[12]) - (m[4] xor h[4]) - (m[6] xor h[6]) - (m[9] xor h[9])) + (m[13] xor h[13])).rotateLeft(19)) +
                h[0]
        q[16] = (q[0] ushr 1 xor (q[0] shl 2) xor q[0].rotateLeft(8) xor q[0].rotateLeft(23)) +
                (q[1] ushr 2 xor (q[1] shl 1) xor q[1].rotateLeft(12) xor q[1].rotateLeft(25)) +
                (q[2] ushr 2 xor (q[2] shl 2) xor q[2].rotateLeft(15) xor q[2].rotateLeft(29)) +
                (q[3] ushr 1 xor (q[3] shl 3) xor q[3].rotateLeft(4) xor q[3].rotateLeft(19)) +
                (q[4] ushr 1 xor (q[4] shl 2) xor q[4].rotateLeft(8) xor q[4].rotateLeft(23)) +
                (q[5] ushr 2 xor (q[5] shl 1) xor q[5].rotateLeft(12) xor q[5].rotateLeft(25)) +
                (q[6] ushr 2 xor (q[6] shl 2) xor q[6].rotateLeft(15) xor q[6].rotateLeft(29)) +
                (q[7] ushr 1 xor (q[7] shl 3) xor q[7].rotateLeft(4) xor q[7].rotateLeft(19)) +
                (q[8] ushr 1 xor (q[8] shl 2) xor q[8].rotateLeft(8) xor q[8].rotateLeft(23)) +
                (q[9] ushr 2 xor (q[9] shl 1) xor q[9].rotateLeft(12) xor q[9].rotateLeft(25)) +
                (q[10] ushr 2 xor (q[10] shl 2) xor q[10].rotateLeft(15) xor q[10].rotateLeft(29)) +
                (q[11] ushr 1 xor (q[11] shl 3) xor q[11].rotateLeft(4) xor q[11].rotateLeft(19)) +
                (q[12] ushr 1 xor (q[12] shl 2) xor q[12].rotateLeft(8) xor q[12].rotateLeft(23)) +
                (q[13] ushr 2 xor (q[13] shl 1) xor q[13].rotateLeft(12) xor q[13].rotateLeft(25)) +
                (q[14] ushr 2 xor (q[14] shl 2) xor q[14].rotateLeft(15) xor q[14].rotateLeft(29)) +
                (q[15] ushr 1 xor (q[15] shl 3) xor q[15].rotateLeft(4) xor q[15].rotateLeft(19)) +
                ((m[0].rotateLeft(1) + m[3].rotateLeft(4) - m[10].rotateLeft(11) + 16 * 0x05555555) xor h[7])
        q[17] = (q[1] ushr 1 xor (q[1] shl 2) xor q[1].rotateLeft(8) xor q[1].rotateLeft(23)) +
                (q[2] ushr 2 xor (q[2] shl 1) xor q[2].rotateLeft(12) xor q[2].rotateLeft(25)) +
                (q[3] ushr 2 xor (q[3] shl 2) xor q[3].rotateLeft(15) xor q[3].rotateLeft(29)) +
                (q[4] ushr 1 xor (q[4] shl 3) xor q[4].rotateLeft(4) xor q[4].rotateLeft(19)) +
                (q[5] ushr 1 xor (q[5] shl 2) xor q[5].rotateLeft(8) xor q[5].rotateLeft(23)) +
                (q[6] ushr 2 xor (q[6] shl 1) xor q[6].rotateLeft(12) xor q[6].rotateLeft(25)) +
                (q[7] ushr 2 xor (q[7] shl 2) xor q[7].rotateLeft(15) xor q[7].rotateLeft(29)) +
                (q[8] ushr 1 xor (q[8] shl 3) xor q[8].rotateLeft(4) xor q[8].rotateLeft(19)) +
                (q[9] ushr 1 xor (q[9] shl 2) xor q[9].rotateLeft(8) xor q[9].rotateLeft(23)) +
                (q[10] ushr 2 xor (q[10] shl 1) xor q[10].rotateLeft(12) xor q[10].rotateLeft(25)) +
                (q[11] ushr 2 xor (q[11] shl 2) xor q[11].rotateLeft(15) xor q[11].rotateLeft(29)) +
                (q[12] ushr 1 xor (q[12] shl 3) xor q[12].rotateLeft(4) xor q[12].rotateLeft(19)) +
                (q[13] ushr 1 xor (q[13] shl 2) xor q[13].rotateLeft(8) xor q[13].rotateLeft(23)) +
                (q[14] ushr 2 xor (q[14] shl 1) xor q[14].rotateLeft(12) xor q[14].rotateLeft(25)) +
                (q[15] ushr 2 xor (q[15] shl 2) xor q[15].rotateLeft(15) xor q[15].rotateLeft(29)) +
                (q[16] ushr 1 xor (q[16] shl 3) xor q[16].rotateLeft(4) xor q[16].rotateLeft(19)) +
                ((m[1].rotateLeft(2) + m[4].rotateLeft(5) - m[11].rotateLeft(12) + 17 * 0x05555555) xor h[8])
        q[18] = q[2] + q[3].rotateLeft(3) +
                q[4] + q[5].rotateLeft(7) +
                q[6] + q[7].rotateLeft(13) +
                q[8] + q[9].rotateLeft(16) +
                q[10] + q[11].rotateLeft(19) +
                q[12] + q[13].rotateLeft(23) +
                q[14] + q[15].rotateLeft(27) +
                (q[16] ushr 1 xor q[16]) + (q[17] ushr 2 xor q[17]) +
                ((m[2].rotateLeft(3) + m[5].rotateLeft(6) - m[12].rotateLeft(13) + 18 * 0x05555555) xor h[9])

        q[19] = q[3] + q[4].rotateLeft(3) +
                q[5] + q[6].rotateLeft(7) +
                q[7] + q[8].rotateLeft(13) +
                q[9] + q[10].rotateLeft(16) +
                q[11] + q[12].rotateLeft(19) +
                q[13] + q[14].rotateLeft(23) +
                q[15] + q[16].rotateLeft(27) +
                (q[17] ushr 1 xor q[17]) + (q[18] ushr 2 xor q[18]) +
                ((m[3].rotateLeft(4) + m[6].rotateLeft(7) - m[13].rotateLeft(14) + 19 * 0x05555555) xor h[10])

        q[20] = q[4] + q[5].rotateLeft(3) +
                q[6] + q[7].rotateLeft(7) +
                q[8] + q[9].rotateLeft(13) +
                q[10] + q[11].rotateLeft(16) +
                q[12] + q[13].rotateLeft(19) +
                q[14] + q[15].rotateLeft(23) +
                q[16] + q[17].rotateLeft(27) +
                (q[18] ushr 1 xor q[18]) + (q[19] ushr 2 xor q[19]) +
                ((m[4].rotateLeft(5) + m[7].rotateLeft(8) - m[14].rotateLeft(15) + 20 * 0x05555555) xor h[11])
        q[21] = q[5] + q[6].rotateLeft(3) +
                q[7] + q[8].rotateLeft(7) +
                q[9] + q[10].rotateLeft(13) +
                q[11] + q[12].rotateLeft(16) +
                q[13] + q[14].rotateLeft(19) +
                q[15] + q[16].rotateLeft(23) +
                q[17] + q[18].rotateLeft(27) +
                (q[19] ushr 1 xor q[19]) + (q[20] ushr 2 xor q[20]) +
                ((m[5].rotateLeft(6) + m[8].rotateLeft(9) - m[15].rotateLeft(16) + 21 * 0x05555555) xor h[12])
        q[22] = q[6] + q[7].rotateLeft(3) +
                q[8] + q[9].rotateLeft(7) +
                q[10] + q[11].rotateLeft(13) +
                q[12] + q[13].rotateLeft(16) +
                q[14] + q[15].rotateLeft(19) +
                q[16] + q[17].rotateLeft(23) +
                q[18] + q[19].rotateLeft(27) +
                (q[20] ushr 1 xor q[20]) + (q[21] ushr 2 xor q[21]) +
                ((m[6].rotateLeft(7) + m[9].rotateLeft(10) - m[0].rotateLeft(1) + 22 * 0x05555555) xor h[13])
        q[23] = q[7] + q[8].rotateLeft(3) +
                q[9] + q[10].rotateLeft(7) +
                q[11] + q[12].rotateLeft(13) +
                q[13] + q[14].rotateLeft(16) +
                q[15] + q[16].rotateLeft(19) +
                q[17] + q[18].rotateLeft(23) +
                q[19] + q[20].rotateLeft(27) +
                (q[21] ushr 1 xor q[21]) + (q[22] ushr 2 xor q[22]) +
                ((m[7].rotateLeft(8) + m[10].rotateLeft(11) - m[1].rotateLeft(2) + 23 * 0x05555555) xor h[14])
        q[24] = q[8] + q[9].rotateLeft(3) +
                q[10] + q[11].rotateLeft(7) +
                q[12] + q[13].rotateLeft(13) +
                q[14] + q[15].rotateLeft(16) +
                q[16] + q[17].rotateLeft(19) +
                q[18] + q[19].rotateLeft(23) +
                q[20] + q[21].rotateLeft(27) +
                (q[22] ushr 1 xor q[22]) + (q[23] ushr 2 xor q[23]) +
                ((m[8].rotateLeft(9) + m[11].rotateLeft(12) - m[2].rotateLeft(3) + 24 * 0x05555555) xor h[15])
        q[25] = q[9] + q[10].rotateLeft(3) +
                q[11] + q[12].rotateLeft(7) +
                q[13] + q[14].rotateLeft(13) +
                q[15] + q[16].rotateLeft(16) +
                q[17] + q[18].rotateLeft(19) +
                q[19] + q[20].rotateLeft(23) +
                q[21] + q[22].rotateLeft(27) +
                (q[23] ushr 1 xor q[23]) + (q[24] ushr 2 xor q[24]) +
                ((m[9].rotateLeft(10) + m[12].rotateLeft(13) - m[3].rotateLeft(4) + 25 * 0x05555555) xor h[0])
        q[26] = q[10] + q[11].rotateLeft(3) +
                q[12] + q[13].rotateLeft(7) +
                q[14] + q[15].rotateLeft(13) +
                q[16] + q[17].rotateLeft(16) +
                q[18] + q[19].rotateLeft(19) +
                q[20] + q[21].rotateLeft(23) +
                q[22] + q[23].rotateLeft(27) +
                (q[24] ushr 1 xor q[24]) + (q[25] ushr 2 xor q[25]) +
                ((m[10].rotateLeft(11) + m[13].rotateLeft(14) - m[4].rotateLeft(5) + 26 * 0x05555555) xor h[1])
        q[27] = q[11] + q[12].rotateLeft(3) +
                q[13] + q[14].rotateLeft(7) +
                q[15] + q[16].rotateLeft(13) +
                q[17] + q[18].rotateLeft(16) +
                q[19] + q[20].rotateLeft(19) +
                q[21] + q[22].rotateLeft(23) +
                q[23] + q[24].rotateLeft(27) +
                (q[25] ushr 1 xor q[25]) + (q[26] ushr 2 xor q[26]) +
                ((m[11].rotateLeft(12) + m[14].rotateLeft(15) - m[5].rotateLeft(6) + 27 * 0x05555555) xor h[2])
        q[28] = q[12] + q[13].rotateLeft(3) +
                q[14] + q[15].rotateLeft(7) +
                q[16] + q[17].rotateLeft(13) +
                q[18] + q[19].rotateLeft(16) +
                q[20] + q[21].rotateLeft(19) +
                q[22] + q[23].rotateLeft(23) +
                q[24] + q[25].rotateLeft(27) +
                (q[26] ushr 1 xor q[26]) + (q[27] ushr 2 xor q[27]) +
                ((m[12].rotateLeft(13) + m[15].rotateLeft(16) - m[6].rotateLeft(7) + 28 * 0x05555555) xor h[3])
        q[29] = q[13] + q[14].rotateLeft(3) +
                q[15] + q[16].rotateLeft(7) +
                q[17] + q[18].rotateLeft(13) +
                q[19] + q[20].rotateLeft(16) +
                q[21] + q[22].rotateLeft(19) +
                q[23] + q[24].rotateLeft(23) +
                q[25] + q[26].rotateLeft(27) +
                (q[27] ushr 1 xor q[27]) + (q[28] ushr 2 xor q[28]) +
                ((m[13].rotateLeft(14) + m[0].rotateLeft(1) - m[7].rotateLeft(8) + 29 * 0x05555555) xor h[4])
        q[30] = q[14] + q[15].rotateLeft(3) +
                q[16] + q[17].rotateLeft(7) +
                q[18] + q[19].rotateLeft(13) +
                q[20] + q[21].rotateLeft(16) +
                q[22] + q[23].rotateLeft(19) +
                q[24] + q[25].rotateLeft(23) +
                q[26] + q[27].rotateLeft(27) +
                (q[28] ushr 1 xor q[28]) + (q[29] ushr 2 xor q[29]) +
                ((m[14].rotateLeft(15) + m[1].rotateLeft(2) - m[8].rotateLeft(9) + 30 * 0x05555555) xor h[5])
        q[31] = q[15] + q[16].rotateLeft(3) +
                q[17] + q[18].rotateLeft(7) +
                q[19] + q[20].rotateLeft(13) +
                q[21] + q[22].rotateLeft(16) +
                q[23] + q[24].rotateLeft(19) +
                q[25] + q[26].rotateLeft(23) +
                q[27] + q[28].rotateLeft(27) +
                (q[29] ushr 1 xor q[29]) + (q[30] ushr 2 xor q[30]) +
                ((m[15].rotateLeft(16) + m[2].rotateLeft(3) - m[9].rotateLeft(10) + 31 * 0x05555555) xor h[6])
        val xl = (q[16] xor q[17] xor q[18] xor q[19] xor q[20] xor q[21] xor q[22] xor q[23])
        val xh = (xl xor q[24] xor q[25] xor q[26] xor q[27] xor q[28] xor q[29] xor q[30] xor q[31])
        h[0] = (xh shl 5 xor (q[16] ushr 5) xor m[0]) + (xl xor q[24] xor q[0])
        h[1] = (xh ushr 7 xor (q[17] shl 8) xor m[1]) + (xl xor q[25] xor q[1])
        h[2] = (xh ushr 5 xor (q[18] shl 5) xor m[2]) + (xl xor q[26] xor q[2])
        h[3] = (xh ushr 1 xor (q[19] shl 5) xor m[3]) + (xl xor q[27] xor q[3])
        h[4] = (xh ushr 3 xor (q[20] shl 0) xor m[4]) + (xl xor q[28] xor q[4])
        h[5] = (xh shl 6 xor (q[21] ushr 6) xor m[5]) + (xl xor q[29] xor q[5])
        h[6] = (xh ushr 4 xor (q[22] shl 6) xor m[6]) + (xl xor q[30] xor q[6])
        h[7] = ((xh ushr 11 xor (q[23] shl 2) xor m[7]) + (xl xor q[31] xor q[7]))
        h[8] = (h[4].rotateLeft(9) + (xh xor q[24] xor m[8]) + (xl shl 8 xor q[23] xor q[8]))
        h[9] = (h[5].rotateLeft(10) + (xh xor q[25] xor m[9]) + (xl ushr 6 xor q[16] xor q[9]))
        h[10] = (h[6].rotateLeft(11) + (xh xor q[26] xor m[10]) + (xl shl 6 xor q[17] xor q[10]))
        h[11] = (h[7].rotateLeft(12) + (xh xor q[27] xor m[11]) + (xl shl 4 xor q[18] xor q[11]))
        h[12] = (h[0].rotateLeft(13) + (xh xor q[28] xor m[12]) + (xl ushr 3 xor q[19] xor q[12]))
        h[13] = (h[1].rotateLeft(14) + (xh xor q[29] xor m[13]) + (xl ushr 4 xor q[20] xor q[13]))
        h[14] = (h[2].rotateLeft(15) + (xh xor q[30] xor m[14]) + (xl ushr 7 xor q[21] xor q[14]))
        h[15] = (h[3].rotateLeft(16) + (xh xor q[31] xor m[15]) + (xl ushr 2 xor q[22] xor q[15]))
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val buf = blockBuffer
        var ptr = flush()
        val bitLen = (blockCount shl 9) + (ptr shl 3)
        buf[ptr++] = 0x80.toByte()
        if (ptr > 56) {
            for (i in ptr..63) buf[i] = 0
            processBlock(buf)
            ptr = 0
        }
        for (i in ptr..55) buf[i] = 0
        encodeLEInt(bitLen.toInt(), buf, 56)
        encodeLEInt((bitLen ushr 32).toInt(), buf, 60)
        processBlock(buf)
        val tmp = h
        h = h2
        h2 = tmp
        FINAL.copyInto(h, 0, 0, 16)
        compress(h2)
        val outLen = digestLength ushr 2
        var i = 0
        var j = 16 - outLen
        while (i < outLen) {
            encodeLEInt(h[j], output, outputOffset + 4 * i)
            i++
            j++
        }
    }

    override fun doInit() {
        m = IntArray(16)
        h = IntArray(16)
        h2 = IntArray(16)
        q = IntArray(32)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        for (i in 0..15) m[i] = decodeLEInt(data, i * 4)
        compress(m)
    }

    companion object {
        private val FINAL = intArrayOf(
            -0x55555560, -0x5555555f, -0x5555555e, -0x5555555d,
            -0x5555555c, -0x5555555b, -0x5555555a, -0x55555559,
            -0x55555558, -0x55555557, -0x55555556, -0x55555555,
            -0x55555554, -0x55555553, -0x55555552, -0x55555551
        )
    }
}
