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

import com.appmattus.crypto.internal.core.encodeBEInt

/**
 * This class implements the Fugue-384 hash function under the
 * [Digest] API.
 *
 * @version $Revision: 159 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal class Fugue384 : FugueCore<Fugue384>() {

    override val digestLength: Int
        get() = 48

    override fun dup(): Fugue384 {
        return Fugue384()
    }

    @Suppress("NAME_SHADOWING", "ReturnCount", "ComplexMethod", "LongMethod")
    override fun process(w: Int, buf: ByteArray?, off: Int, num: Int) {
        var w = w
        var off = off
        var num = num
        when (rshift) {
            1 -> {
                s[7] = s[7] xor s[27]
                s[27] = w
                s[35] = s[35] xor s[27]
                s[28] = s[28] xor s[18]
                s[31] = s[31] xor s[21]
                s[24] = s[24] xor s[28]
                s[25] = s[25] xor s[29]
                s[26] = s[26] xor s[30]
                s[6] = s[6] xor s[28]
                s[7] = s[7] xor s[29]
                s[8] = s[8] xor s[30]
                smix(24, 25, 26, 27)
                s[21] = s[21] xor s[25]
                s[22] = s[22] xor s[26]
                s[23] = s[23] xor s[27]
                s[3] = s[3] xor s[25]
                s[4] = s[4] xor s[26]
                s[5] = s[5] xor s[27]
                smix(21, 22, 23, 24)
                s[18] = s[18] xor s[22]
                s[19] = s[19] xor s[23]
                s[20] = s[20] xor s[24]
                s[0] = s[0] xor s[22]
                s[1] = s[1] xor s[23]
                s[2] = s[2] xor s[24]
                smix(18, 19, 20, 21)
                if (num-- <= 0) {
                    rshift = 2
                    return
                }
                w = (buf!![off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
                s[34] = s[34] xor s[18]
                s[18] = w
                s[26] = s[26] xor s[18]
                s[19] = s[19] xor s[9]
                s[22] = s[22] xor s[12]
                s[15] = s[15] xor s[19]
                s[16] = s[16] xor s[20]
                s[17] = s[17] xor s[21]
                s[33] = s[33] xor s[19]
                s[34] = s[34] xor s[20]
                s[35] = s[35] xor s[21]
                smix(15, 16, 17, 18)
                s[12] = s[12] xor s[16]
                s[13] = s[13] xor s[17]
                s[14] = s[14] xor s[18]
                s[30] = s[30] xor s[16]
                s[31] = s[31] xor s[17]
                s[32] = s[32] xor s[18]
                smix(12, 13, 14, 15)
                s[9] = s[9] xor s[13]
                s[10] = s[10] xor s[14]
                s[11] = s[11] xor s[15]
                s[27] = s[27] xor s[13]
                s[28] = s[28] xor s[14]
                s[29] = s[29] xor s[15]
                smix(9, 10, 11, 12)
                if (num-- <= 0) {
                    rshift = 3
                    return
                }
                w = (buf[off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
                s[25] = s[25] xor s[9]
                s[9] = w
                s[17] = s[17] xor s[9]
                s[10] = s[10] xor s[0]
                s[13] = s[13] xor s[3]
                s[6] = s[6] xor s[10]
                s[7] = s[7] xor s[11]
                s[8] = s[8] xor s[12]
                s[24] = s[24] xor s[10]
                s[25] = s[25] xor s[11]
                s[26] = s[26] xor s[12]
                smix(6, 7, 8, 9)
                s[3] = s[3] xor s[7]
                s[4] = s[4] xor s[8]
                s[5] = s[5] xor s[9]
                s[21] = s[21] xor s[7]
                s[22] = s[22] xor s[8]
                s[23] = s[23] xor s[9]
                smix(3, 4, 5, 6)
                s[0] = s[0] xor s[4]
                s[1] = s[1] xor s[5]
                s[2] = s[2] xor s[6]
                s[18] = s[18] xor s[4]
                s[19] = s[19] xor s[5]
                s[20] = s[20] xor s[6]
                smix(0, 1, 2, 3)
                if (num-- <= 0) {
                    rshift = 0
                    return
                }
                w = (buf[off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
            }
            2 -> {
                s[34] = s[34] xor s[18]
                s[18] = w
                s[26] = s[26] xor s[18]
                s[19] = s[19] xor s[9]
                s[22] = s[22] xor s[12]
                s[15] = s[15] xor s[19]
                s[16] = s[16] xor s[20]
                s[17] = s[17] xor s[21]
                s[33] = s[33] xor s[19]
                s[34] = s[34] xor s[20]
                s[35] = s[35] xor s[21]
                smix(15, 16, 17, 18)
                s[12] = s[12] xor s[16]
                s[13] = s[13] xor s[17]
                s[14] = s[14] xor s[18]
                s[30] = s[30] xor s[16]
                s[31] = s[31] xor s[17]
                s[32] = s[32] xor s[18]
                smix(12, 13, 14, 15)
                s[9] = s[9] xor s[13]
                s[10] = s[10] xor s[14]
                s[11] = s[11] xor s[15]
                s[27] = s[27] xor s[13]
                s[28] = s[28] xor s[14]
                s[29] = s[29] xor s[15]
                smix(9, 10, 11, 12)
                if (num-- <= 0) {
                    rshift = 3
                    return
                }
                w = (buf!![off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
                s[25] = s[25] xor s[9]
                s[9] = w
                s[17] = s[17] xor s[9]
                s[10] = s[10] xor s[0]
                s[13] = s[13] xor s[3]
                s[6] = s[6] xor s[10]
                s[7] = s[7] xor s[11]
                s[8] = s[8] xor s[12]
                s[24] = s[24] xor s[10]
                s[25] = s[25] xor s[11]
                s[26] = s[26] xor s[12]
                smix(6, 7, 8, 9)
                s[3] = s[3] xor s[7]
                s[4] = s[4] xor s[8]
                s[5] = s[5] xor s[9]
                s[21] = s[21] xor s[7]
                s[22] = s[22] xor s[8]
                s[23] = s[23] xor s[9]
                smix(3, 4, 5, 6)
                s[0] = s[0] xor s[4]
                s[1] = s[1] xor s[5]
                s[2] = s[2] xor s[6]
                s[18] = s[18] xor s[4]
                s[19] = s[19] xor s[5]
                s[20] = s[20] xor s[6]
                smix(0, 1, 2, 3)
                if (num-- <= 0) {
                    rshift = 0
                    return
                }
                w = (buf[off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
            }
            3 -> {
                s[25] = s[25] xor s[9]
                s[9] = w
                s[17] = s[17] xor s[9]
                s[10] = s[10] xor s[0]
                s[13] = s[13] xor s[3]
                s[6] = s[6] xor s[10]
                s[7] = s[7] xor s[11]
                s[8] = s[8] xor s[12]
                s[24] = s[24] xor s[10]
                s[25] = s[25] xor s[11]
                s[26] = s[26] xor s[12]
                smix(6, 7, 8, 9)
                s[3] = s[3] xor s[7]
                s[4] = s[4] xor s[8]
                s[5] = s[5] xor s[9]
                s[21] = s[21] xor s[7]
                s[22] = s[22] xor s[8]
                s[23] = s[23] xor s[9]
                smix(3, 4, 5, 6)
                s[0] = s[0] xor s[4]
                s[1] = s[1] xor s[5]
                s[2] = s[2] xor s[6]
                s[18] = s[18] xor s[4]
                s[19] = s[19] xor s[5]
                s[20] = s[20] xor s[6]
                smix(0, 1, 2, 3)
                if (num-- <= 0) {
                    rshift = 0
                    return
                }
                w = (buf!![off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
            }
        }
        while (true) {

            /* ================ */
            s[16] = s[16] xor s[0]
            s[0] = w
            s[8] = s[8] xor s[0]
            s[1] = s[1] xor s[27]
            s[4] = s[4] xor s[30]
            s[33] = s[33] xor s[1]
            s[34] = s[34] xor s[2]
            s[35] = s[35] xor s[3]
            s[15] = s[15] xor s[1]
            s[16] = s[16] xor s[2]
            s[17] = s[17] xor s[3]
            smix(33, 34, 35, 0)
            s[30] = s[30] xor s[34]
            s[31] = s[31] xor s[35]
            s[32] = s[32] xor s[0]
            s[12] = s[12] xor s[34]
            s[13] = s[13] xor s[35]
            s[14] = s[14] xor s[0]
            smix(30, 31, 32, 33)
            s[27] = s[27] xor s[31]
            s[28] = s[28] xor s[32]
            s[29] = s[29] xor s[33]
            s[9] = s[9] xor s[31]
            s[10] = s[10] xor s[32]
            s[11] = s[11] xor s[33]
            smix(27, 28, 29, 30)
            if (num-- <= 0) {
                rshift = 1
                return
            }
            w = (buf!![off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
            /* ================ */
            s[7] = s[7] xor s[27]
            s[27] = w
            s[35] = s[35] xor s[27]
            s[28] = s[28] xor s[18]
            s[31] = s[31] xor s[21]
            s[24] = s[24] xor s[28]
            s[25] = s[25] xor s[29]
            s[26] = s[26] xor s[30]
            s[6] = s[6] xor s[28]
            s[7] = s[7] xor s[29]
            s[8] = s[8] xor s[30]
            smix(24, 25, 26, 27)
            s[21] = s[21] xor s[25]
            s[22] = s[22] xor s[26]
            s[23] = s[23] xor s[27]
            s[3] = s[3] xor s[25]
            s[4] = s[4] xor s[26]
            s[5] = s[5] xor s[27]
            smix(21, 22, 23, 24)
            s[18] = s[18] xor s[22]
            s[19] = s[19] xor s[23]
            s[20] = s[20] xor s[24]
            s[0] = s[0] xor s[22]
            s[1] = s[1] xor s[23]
            s[2] = s[2] xor s[24]
            smix(18, 19, 20, 21)
            if (num-- <= 0) {
                rshift = 2
                return
            }
            w = (buf[off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
            /* ================ */
            s[34] = s[34] xor s[18]
            s[18] = w
            s[26] = s[26] xor s[18]
            s[19] = s[19] xor s[9]
            s[22] = s[22] xor s[12]
            s[15] = s[15] xor s[19]
            s[16] = s[16] xor s[20]
            s[17] = s[17] xor s[21]
            s[33] = s[33] xor s[19]
            s[34] = s[34] xor s[20]
            s[35] = s[35] xor s[21]
            smix(15, 16, 17, 18)
            s[12] = s[12] xor s[16]
            s[13] = s[13] xor s[17]
            s[14] = s[14] xor s[18]
            s[30] = s[30] xor s[16]
            s[31] = s[31] xor s[17]
            s[32] = s[32] xor s[18]
            smix(12, 13, 14, 15)
            s[9] = s[9] xor s[13]
            s[10] = s[10] xor s[14]
            s[11] = s[11] xor s[15]
            s[27] = s[27] xor s[13]
            s[28] = s[28] xor s[14]
            s[29] = s[29] xor s[15]
            smix(9, 10, 11, 12)
            if (num-- <= 0) {
                rshift = 3
                return
            }
            w = (buf[off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
            /* ================ */
            s[25] = s[25] xor s[9]
            s[9] = w
            s[17] = s[17] xor s[9]
            s[10] = s[10] xor s[0]
            s[13] = s[13] xor s[3]
            s[6] = s[6] xor s[10]
            s[7] = s[7] xor s[11]
            s[8] = s[8] xor s[12]
            s[24] = s[24] xor s[10]
            s[25] = s[25] xor s[11]
            s[26] = s[26] xor s[12]
            smix(6, 7, 8, 9)
            s[3] = s[3] xor s[7]
            s[4] = s[4] xor s[8]
            s[5] = s[5] xor s[9]
            s[21] = s[21] xor s[7]
            s[22] = s[22] xor s[8]
            s[23] = s[23] xor s[9]
            smix(3, 4, 5, 6)
            s[0] = s[0] xor s[4]
            s[1] = s[1] xor s[5]
            s[2] = s[2] xor s[6]
            s[18] = s[18] xor s[4]
            s[19] = s[19] xor s[5]
            s[20] = s[20] xor s[6]
            smix(0, 1, 2, 3)
            if (num-- <= 0) {
                rshift = 0
                return
            }
            w = (buf[off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
        }
    }

    override fun processFinal(out: ByteArray?) {
        ror(9 * rshift, 36)
        repeat(18) {
            ror(3, 36)
            cmix36()
            smix(0, 1, 2, 3)
        }
        repeat(13) {
            s[4] = s[4] xor s[0]
            s[12] = s[12] xor s[0]
            s[24] = s[24] xor s[0]
            ror(12, 36)
            smix(0, 1, 2, 3)
            s[4] = s[4] xor s[0]
            s[13] = s[13] xor s[0]
            s[24] = s[24] xor s[0]
            ror(12, 36)
            smix(0, 1, 2, 3)
            s[4] = s[4] xor s[0]
            s[13] = s[13] xor s[0]
            s[25] = s[25] xor s[0]
            ror(11, 36)
            smix(0, 1, 2, 3)
        }
        s[4] = s[4] xor s[0]
        s[12] = s[12] xor s[0]
        s[24] = s[24] xor s[0]
        encodeBEInt(s[1], out!!, 0)
        encodeBEInt(s[2], out, 4)
        encodeBEInt(s[3], out, 8)
        encodeBEInt(s[4], out, 12)
        encodeBEInt(s[12], out, 16)
        encodeBEInt(s[13], out, 20)
        encodeBEInt(s[14], out, 24)
        encodeBEInt(s[15], out, 28)
        encodeBEInt(s[24], out, 32)
        encodeBEInt(s[25], out, 36)
        encodeBEInt(s[26], out, 40)
        encodeBEInt(s[27], out, 44)
    }

    override val iV: IntArray
        get() = Companion.iV

    companion object {
        val iV = intArrayOf(
            -0x559e13f3, 0x31252e1f, -0x5fe24b39, 0x00600985,
            0x215ef44a, 0x741b5e9c, -0x596c166, 0x473eb040,
            -0x1afd5176, -0x5663da20, -0x436aae84, 0x5c1095a1
        )
    }
}
