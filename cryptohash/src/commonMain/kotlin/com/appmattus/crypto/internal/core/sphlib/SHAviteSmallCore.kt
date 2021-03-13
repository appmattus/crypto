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

import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 * This class implements SHAvite-224 and SHAvite-256.
 *
 * @version $Revision: 222 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("MagicNumber")
internal abstract class SHAviteSmallCore<D : SHAviteSmallCore<D>> : DigestEngine<D>() {
    private lateinit var h: IntArray
    private lateinit var rk: IntArray

    override val blockLength: Int
        get() = 64

    override fun copyState(dest: D): D {
        h.copyInto(dest.h, 0, 0, h.size)
        return super.copyState(dest)
    }

    override fun engineReset() {
        initVal.copyInto(h, 0, 0, h.size)
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return the initial value
     */
    protected abstract val initVal: IntArray

    @Suppress("CascadeIf")
    override fun doPadding(output: ByteArray, outputOffset: Int) {
        var ptr = flush()
        val bc = blockCount
        val bitLen = (bc shl 9) + (ptr shl 3)
        var cnt0 = bitLen.toInt()
        var cnt1 = (bitLen ushr 32).toInt()
        val buf = blockBuffer
        if (ptr == 0) {
            buf[0] = 0x80.toByte()
            for (i in 1..53) buf[i] = 0
            cnt1 = 0
            cnt0 = cnt1
        } else if (ptr < 54) {
            buf[ptr++] = 0x80.toByte()
            while (ptr < 54) buf[ptr++] = 0
        } else {
            buf[ptr++] = 0x80.toByte()
            while (ptr < 64) buf[ptr++] = 0
            process(buf, cnt0, cnt1)
            for (i in 0..53) buf[i] = 0
            cnt1 = 0
            cnt0 = cnt1
        }
        encodeLEInt(bitLen.toInt(), buf, 54)
        encodeLEInt((bitLen ushr 32).toInt(), buf, 58)
        val dlen = digestLength
        buf[62] = (dlen shl 3).toByte()
        buf[63] = (dlen ushr 5).toByte()
        process(buf, cnt0, cnt1)
        var i = 0
        while (i < dlen) {
            encodeLEInt(h[i ushr 2], output, outputOffset + i)
            i += 4
        }
    }

    override fun doInit() {
        h = IntArray(8)
        rk = IntArray(144)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        val bitLen = blockCount + 1 shl 9
        process(data, bitLen.toInt(), (bitLen ushr 32).toInt())
    }

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    private fun process(data: ByteArray, cnt0: Int, cnt1: Int) {
        var p0: Int
        var p1: Int
        var p2: Int
        var p3: Int
        var p4: Int
        var p5: Int
        var p6: Int
        var p7: Int
        var u: Int
        u = 0
        while (u < 16) {
            rk[u + 0] = decodeLEInt(data, (u shl 2) + 0)
            rk[u + 1] = decodeLEInt(data, (u shl 2) + 4)
            rk[u + 2] = decodeLEInt(data, (u shl 2) + 8)
            rk[u + 3] = decodeLEInt(data, (u shl 2) + 12)
            u += 4
        }
        repeat(4) {
            repeat(2) {
                var x0: Int
                var x1: Int
                var x2: Int
                var x3: Int
                var t0: Int
                var t1: Int
                var t2: Int
                var t3: Int
                x0 = rk[u - 15]
                x1 = rk[u - 14]
                x2 = rk[u - 13]
                x3 = rk[u - 16]
                t0 = (AES0[x0 and 0xFF]
                        xor AES1[x1 ushr 8 and 0xFF]
                        xor AES2[x2 ushr 16 and 0xFF]
                        xor AES3[x3 ushr 24])
                t1 = (AES0[x1 and 0xFF]
                        xor AES1[x2 ushr 8 and 0xFF]
                        xor AES2[x3 ushr 16 and 0xFF]
                        xor AES3[x0 ushr 24])
                t2 = (AES0[x2 and 0xFF]
                        xor AES1[x3 ushr 8 and 0xFF]
                        xor AES2[x0 ushr 16 and 0xFF]
                        xor AES3[x1 ushr 24])
                t3 = (AES0[x3 and 0xFF]
                        xor AES1[x0 ushr 8 and 0xFF]
                        xor AES2[x1 ushr 16 and 0xFF]
                        xor AES3[x2 ushr 24])
                rk[u + 0] = t0 xor rk[u - 4]
                rk[u + 1] = t1 xor rk[u - 3]
                rk[u + 2] = t2 xor rk[u - 2]
                rk[u + 3] = t3 xor rk[u - 1]
                if (u == 16) {
                    rk[16] = rk[16] xor cnt0
                    rk[17] = rk[17] xor cnt1.inv()
                } else if (u == 56) {
                    rk[57] = rk[57] xor cnt1
                    rk[58] = rk[58] xor cnt0.inv()
                }
                u += 4
                x0 = rk[u - 15]
                x1 = rk[u - 14]
                x2 = rk[u - 13]
                x3 = rk[u - 16]
                t0 = (AES0[x0 and 0xFF]
                        xor AES1[x1 ushr 8 and 0xFF]
                        xor AES2[x2 ushr 16 and 0xFF]
                        xor AES3[x3 ushr 24])
                t1 = (AES0[x1 and 0xFF]
                        xor AES1[x2 ushr 8 and 0xFF]
                        xor AES2[x3 ushr 16 and 0xFF]
                        xor AES3[x0 ushr 24])
                t2 = (AES0[x2 and 0xFF]
                        xor AES1[x3 ushr 8 and 0xFF]
                        xor AES2[x0 ushr 16 and 0xFF]
                        xor AES3[x1 ushr 24])
                t3 = (AES0[x3 and 0xFF]
                        xor AES1[x0 ushr 8 and 0xFF]
                        xor AES2[x1 ushr 16 and 0xFF]
                        xor AES3[x2 ushr 24])
                rk[u + 0] = t0 xor rk[u - 4]
                rk[u + 1] = t1 xor rk[u - 3]
                rk[u + 2] = t2 xor rk[u - 2]
                rk[u + 3] = t3 xor rk[u - 1]
                if (u == 84) {
                    rk[86] = rk[86] xor cnt1
                    rk[87] = rk[87] xor cnt0.inv()
                } else if (u == 124) {
                    rk[124] = rk[124] xor cnt0
                    rk[127] = rk[127] xor cnt1.inv()
                }
                u += 4
            }
            repeat(4) {
                rk[u + 0] = rk[u - 16] xor rk[u - 3]
                rk[u + 1] = rk[u - 15] xor rk[u - 2]
                rk[u + 2] = rk[u - 14] xor rk[u - 1]
                rk[u + 3] = rk[u - 13] xor rk[u - 0]
                u += 4
            }
        }
        p0 = h[0x0]
        p1 = h[0x1]
        p2 = h[0x2]
        p3 = h[0x3]
        p4 = h[0x4]
        p5 = h[0x5]
        p6 = h[0x6]
        p7 = h[0x7]
        u = 0
        repeat(6) {
            var x0: Int
            var x1: Int
            var x2: Int
            var x3: Int
            var t0: Int
            var t1: Int
            var t2: Int
            var t3: Int
            x0 = p4 xor rk[u++]
            x1 = p5 xor rk[u++]
            x2 = p6 xor rk[u++]
            x3 = p7 xor rk[u++]
            t0 = (AES0[x0 and 0xFF]
                    xor AES1[x1 ushr 8 and 0xFF]
                    xor AES2[x2 ushr 16 and 0xFF]
                    xor AES3[x3 ushr 24])
            t1 = (AES0[x1 and 0xFF]
                    xor AES1[x2 ushr 8 and 0xFF]
                    xor AES2[x3 ushr 16 and 0xFF]
                    xor AES3[x0 ushr 24])
            t2 = (AES0[x2 and 0xFF]
                    xor AES1[x3 ushr 8 and 0xFF]
                    xor AES2[x0 ushr 16 and 0xFF]
                    xor AES3[x1 ushr 24])
            t3 = (AES0[x3 and 0xFF]
                    xor AES1[x0 ushr 8 and 0xFF]
                    xor AES2[x1 ushr 16 and 0xFF]
                    xor AES3[x2 ushr 24])
            x0 = t0 xor rk[u++]
            x1 = t1 xor rk[u++]
            x2 = t2 xor rk[u++]
            x3 = t3 xor rk[u++]
            t0 = (AES0[x0 and 0xFF]
                    xor AES1[x1 ushr 8 and 0xFF]
                    xor AES2[x2 ushr 16 and 0xFF]
                    xor AES3[x3 ushr 24])
            t1 = (AES0[x1 and 0xFF]
                    xor AES1[x2 ushr 8 and 0xFF]
                    xor AES2[x3 ushr 16 and 0xFF]
                    xor AES3[x0 ushr 24])
            t2 = (AES0[x2 and 0xFF]
                    xor AES1[x3 ushr 8 and 0xFF]
                    xor AES2[x0 ushr 16 and 0xFF]
                    xor AES3[x1 ushr 24])
            t3 = (AES0[x3 and 0xFF]
                    xor AES1[x0 ushr 8 and 0xFF]
                    xor AES2[x1 ushr 16 and 0xFF]
                    xor AES3[x2 ushr 24])
            x0 = t0 xor rk[u++]
            x1 = t1 xor rk[u++]
            x2 = t2 xor rk[u++]
            x3 = t3 xor rk[u++]
            t0 = (AES0[x0 and 0xFF]
                    xor AES1[x1 ushr 8 and 0xFF]
                    xor AES2[x2 ushr 16 and 0xFF]
                    xor AES3[x3 ushr 24])
            t1 = (AES0[x1 and 0xFF]
                    xor AES1[x2 ushr 8 and 0xFF]
                    xor AES2[x3 ushr 16 and 0xFF]
                    xor AES3[x0 ushr 24])
            t2 = (AES0[x2 and 0xFF]
                    xor AES1[x3 ushr 8 and 0xFF]
                    xor AES2[x0 ushr 16 and 0xFF]
                    xor AES3[x1 ushr 24])
            t3 = (AES0[x3 and 0xFF]
                    xor AES1[x0 ushr 8 and 0xFF]
                    xor AES2[x1 ushr 16 and 0xFF]
                    xor AES3[x2 ushr 24])
            p0 = p0 xor t0
            p1 = p1 xor t1
            p2 = p2 xor t2
            p3 = p3 xor t3
            x0 = p0 xor rk[u++]
            x1 = p1 xor rk[u++]
            x2 = p2 xor rk[u++]
            x3 = p3 xor rk[u++]
            t0 = (AES0[x0 and 0xFF]
                    xor AES1[x1 ushr 8 and 0xFF]
                    xor AES2[x2 ushr 16 and 0xFF]
                    xor AES3[x3 ushr 24])
            t1 = (AES0[x1 and 0xFF]
                    xor AES1[x2 ushr 8 and 0xFF]
                    xor AES2[x3 ushr 16 and 0xFF]
                    xor AES3[x0 ushr 24])
            t2 = (AES0[x2 and 0xFF]
                    xor AES1[x3 ushr 8 and 0xFF]
                    xor AES2[x0 ushr 16 and 0xFF]
                    xor AES3[x1 ushr 24])
            t3 = (AES0[x3 and 0xFF]
                    xor AES1[x0 ushr 8 and 0xFF]
                    xor AES2[x1 ushr 16 and 0xFF]
                    xor AES3[x2 ushr 24])
            x0 = t0 xor rk[u++]
            x1 = t1 xor rk[u++]
            x2 = t2 xor rk[u++]
            x3 = t3 xor rk[u++]
            t0 = (AES0[x0 and 0xFF]
                    xor AES1[x1 ushr 8 and 0xFF]
                    xor AES2[x2 ushr 16 and 0xFF]
                    xor AES3[x3 ushr 24])
            t1 = (AES0[x1 and 0xFF]
                    xor AES1[x2 ushr 8 and 0xFF]
                    xor AES2[x3 ushr 16 and 0xFF]
                    xor AES3[x0 ushr 24])
            t2 = (AES0[x2 and 0xFF]
                    xor AES1[x3 ushr 8 and 0xFF]
                    xor AES2[x0 ushr 16 and 0xFF]
                    xor AES3[x1 ushr 24])
            t3 = (AES0[x3 and 0xFF]
                    xor AES1[x0 ushr 8 and 0xFF]
                    xor AES2[x1 ushr 16 and 0xFF]
                    xor AES3[x2 ushr 24])
            x0 = t0 xor rk[u++]
            x1 = t1 xor rk[u++]
            x2 = t2 xor rk[u++]
            x3 = t3 xor rk[u++]
            t0 = (AES0[x0 and 0xFF]
                    xor AES1[x1 ushr 8 and 0xFF]
                    xor AES2[x2 ushr 16 and 0xFF]
                    xor AES3[x3 ushr 24])
            t1 = (AES0[x1 and 0xFF]
                    xor AES1[x2 ushr 8 and 0xFF]
                    xor AES2[x3 ushr 16 and 0xFF]
                    xor AES3[x0 ushr 24])
            t2 = (AES0[x2 and 0xFF]
                    xor AES1[x3 ushr 8 and 0xFF]
                    xor AES2[x0 ushr 16 and 0xFF]
                    xor AES3[x1 ushr 24])
            t3 = (AES0[x3 and 0xFF]
                    xor AES1[x0 ushr 8 and 0xFF]
                    xor AES2[x1 ushr 16 and 0xFF]
                    xor AES3[x2 ushr 24])
            p4 = p4 xor t0
            p5 = p5 xor t1
            p6 = p6 xor t2
            p7 = p7 xor t3
        }
        h[0x0] = h[0x0] xor p0
        h[0x1] = h[0x1] xor p1
        h[0x2] = h[0x2] xor p2
        h[0x3] = h[0x3] xor p3
        h[0x4] = h[0x4] xor p4
        h[0x5] = h[0x5] xor p5
        h[0x6] = h[0x6] xor p6
        h[0x7] = h[0x7] xor p7
    }

    override fun toString(): String {
        return "SHAvite-" + (digestLength shl 3)
    }

    companion object {
        private val AES0 = intArrayOf(
            -0x5a9c9c3a, -0x7b838308, -0x66888812, -0x7284840a,
            0x0DF2F2FF, -0x4294942a, -0x4e909022, 0x54C5C591,
            0x50303060, 0x03010102, -0x56989832, 0x7D2B2B56,
            0x19FEFEE7, 0x62D7D7B5, -0x195454b3, -0x65898914,
            0x45CACA8F, -0x627d7de1, 0x40C9C989, -0x78828206,
            0x15FAFAEF, -0x14a6a64e, -0x36b8b872, 0x0BF0F0FB,
            -0x135252bf, 0x67D4D4B3, -0x25d5da1, -0x155050bb,
            -0x406363dd, -0x85b5bad, -0x698d8d1c, 0x5BC0C09B,
            -0x3d48488b, 0x1CFDFDE1, -0x516c6cc3, 0x6A26264C,
            0x5A36366C, 0x413F3F7E, 0x02F7F7F5, 0x4FCCCC83,
            0x5C343468, -0xb5a5aaf, 0x34E5E5D1, 0x08F1F1F9,
            -0x6c8e8e1e, 0x73D8D8AB, 0x53313162, 0x3F15152A,
            0x0C040408, 0x52C7C795, 0x65232346, 0x5EC3C39D,
            0x28181830, -0x5e6969c9, 0x0F05050A, -0x4a6565d1,
            0x0907070E, 0x36121224, -0x647f7fe5, 0x3DE2E2DF,
            0x26EBEBCD, 0x6927274E, -0x324d4d81, -0x608a8a16,
            0x1B090912, -0x617c7ce3, 0x742C2C58, 0x2E1A1A34,
            0x2D1B1B36, -0x4d919124, -0x11a5a54c, -0x45f5fa5,
            -0x9adad5c, 0x4D3B3B76, 0x61D6D6B7, -0x314c4c83,
            0x7B292952, 0x3EE3E3DD, 0x712F2F5E, -0x687b7bed,
            -0xaacac5a, 0x68D1D1B9, 0x00000000, 0x2CEDEDC1,
            0x60202040, 0x1FFCFCE3, -0x374e4e87, -0x12a4a44a,
            -0x4195952c, 0x46CBCB8D, -0x26414199, 0x4B393972,
            -0x21b5b56c, -0x2bb3b368, -0x17a7a750, 0x4ACFCF85,
            0x6BD0D0BB, 0x2AEFEFC5, -0x1a5555b1, 0x16FBFBED,
            -0x3abcbc7a, -0x28b2b266, 0x55333366, -0x6b7a7aef,
            -0x30baba76, 0x10F9F9E9, 0x06020204, -0x7e808002,
            -0xfafaf60, 0x443C3C78, -0x456060db, -0x1c5757b5,
            -0xcaeae5e, -0x15c5ca3, -0x3fbfbf80, -0x757070fb,
            -0x526d6dc1, -0x436262df, 0x48383870, 0x04F5F5F1,
            -0x2043439d, -0x3e494989, 0x75DADAAF, 0x63212142,
            0x30101020, 0x1AFFFFE5, 0x0EF3F3FD, 0x6DD2D2BF,
            0x4CCDCD81, 0x140C0C18, 0x35131326, 0x2FECECC3,
            -0x1ea0a042, -0x5d6868cb, -0x33bbbb78, 0x3917172E,
            0x57C4C493, -0xd5858ab, -0x7d818104, 0x473D3D7A,
            -0x539b9b38, -0x18a2a246, 0x2B191932, -0x6a8c8c1a,
            -0x5f9f9f40, -0x677e7ee7, -0x2eb0b062, 0x7FDCDCA3,
            0x66222244, 0x7E2A2A54, -0x546f6fc5, -0x7c7777f5,
            -0x35b9b974, 0x29EEEEC7, -0x2c474795, 0x3C141428,
            0x79DEDEA7, -0x1da1a144, 0x1D0B0B16, 0x76DBDBAD,
            0x3BE0E0DB, 0x56323264, 0x4E3A3A74, 0x1E0A0A14,
            -0x24b6b66e, 0x0A06060C, 0x6C242448, -0x1ba3a348,
            0x5DC2C29F, 0x6ED3D3BD, -0x105353bd, -0x599d9d3c,
            -0x576e6ec7, -0x5b6a6acf, 0x37E4E4D3, -0x7486860e,
            0x32E7E7D5, 0x43C8C88B, 0x5937376E, -0x48929226,
            -0x737272ff, 0x64D5D5B1, -0x2db1b164, -0x1f5656b7,
            -0x4b939328, -0x5a9a954, 0x07F4F4F3, 0x25EAEACF,
            -0x509a9a36, -0x7185850c, -0x165151b9, 0x18080810,
            -0x2a454591, -0x77878710, 0x6F25254A, 0x722E2E5C,
            0x241C1C38, -0xe5959a9, -0x384b4b8d, 0x51C6C697,
            0x23E8E8CB, 0x7CDDDDA1, -0x638b8b18, 0x211F1F3E,
            -0x22b4b46a, -0x2342429f, -0x797474f3, -0x7a7575f1,
            -0x6f8f8f20, 0x423E3E7C, -0x3b4a4a8f, -0x55999934,
            -0x27b7b770, 0x05030306, 0x01F6F6F7, 0x120E0E1C,
            -0x5c9e9e3e, 0x5F35356A, -0x6a8a852, -0x2f464697,
            -0x6e7979e9, 0x58C1C199, 0x271D1D3A, -0x466161d9,
            0x38E1E1D9, 0x13F8F8EB, -0x4c6767d5, 0x33111122,
            -0x4496962e, 0x70D9D9A9, -0x767171f9, -0x586b6bcd,
            -0x496464d3, 0x221E1E3C, -0x6d7878eb, 0x20E9E9C9,
            0x49CECE87, -0xaaaa56, 0x78282850, 0x7ADFDFA5,
            -0x707373fd, -0x75e5ea7, -0x7f7676f7, 0x170D0D1A,
            -0x2540409b, 0x31E6E6D7, -0x39bdbd7c, -0x47979730,
            -0x3cbebe7e, -0x4f6666d7, 0x772D2D5A, 0x110F0F1E,
            -0x344f4f85, -0x3abab58, -0x29444493, 0x3A16162C
        )
        private val AES1 = intArrayOf(
            0x6363C6A5, 0x7C7CF884, 0x7777EE99, 0x7B7BF68D,
            -0xd0d00f3, 0x6B6BD6BD, 0x6F6FDEB1, -0x3a3a6eac,
            0x30306050, 0x01010203, 0x6767CEA9, 0x2B2B567D,
            -0x10118e7, -0x28284a9e, -0x5454b21a, 0x7676EC9A,
            -0x353570bb, -0x7d7de063, -0x363676c0, 0x7D7DFA87,
            -0x50510eb, 0x5959B2EB, 0x47478EC9, -0xf0f04f5,
            -0x5252be14, -0x2b2b4c99, -0x5d5da003, -0x5050ba16,
            -0x6363dc41, -0x5b5bac09, 0x7272E496, -0x3f3f64a5,
            -0x48488a3e, -0x2021ee4, -0x6c6cc252, 0x26264C6A,
            0x36366C5A, 0x3F3F7E41, -0x8080afe, -0x33337cb1,
            0x3434685C, -0x5a5aae0c, -0x1a1a2ecc, -0xe0e06f8,
            0x7171E293, -0x2727548d, 0x31316253, 0x15152A3F,
            0x0404080C, -0x38386aae, 0x23234665, -0x3c3c62a2,
            0x18183028, -0x6969c85f, 0x05050A0F, -0x6565d04b,
            0x07070E09, 0x12122436, -0x7f7fe465, -0x1d1d20c3,
            -0x141432da, 0x27274E69, -0x4d4d8033, 0x7575EA9F,
            0x0909121B, -0x7c7ce262, 0x2C2C5874, 0x1A1A342E,
            0x1B1B362D, 0x6E6EDCB2, 0x5A5AB4EE, -0x5f5fa405,
            0x5252A4F6, 0x3B3B764D, -0x2929489f, -0x4c4c8232,
            0x2929527B, -0x1c1c22c2, 0x2F2F5E71, -0x7b7bec69,
            0x5353A6F5, -0x2e2e4698, 0x00000000, -0x12123ed4,
            0x20204060, -0x3031ce1, -0x4e4e8638, 0x5B5BB6ED,
            0x6A6AD4BE, -0x343472ba, -0x41419827, 0x3939724B,
            0x4A4A94DE, 0x4C4C98D4, 0x5858B0E8, -0x30307ab6,
            -0x2f2f4495, -0x10103ad6, -0x5555b01b, -0x40412ea,
            0x434386C5, 0x4D4D9AD7, 0x33336655, -0x7a7aee6c,
            0x45458ACF, -0x60616f0, 0x02020406, 0x7F7FFE81,
            0x5050A0F0, 0x3C3C7844, -0x6060da46, -0x5757b41d,
            0x5151A2F3, -0x5c5ca202, 0x404080C0, -0x7070fa76,
            -0x6d6dc053, -0x6262de44, 0x38387048, -0xa0a0efc,
            -0x43439c21, -0x4949883f, -0x2525508b, 0x21214263,
            0x10102030, -0x1ae6, -0xc0c02f2, -0x2d2d4093,
            -0x32327eb4, 0x0C0C1814, 0x13132635, -0x13133cd1,
            0x5F5FBEE1, -0x6868ca5e, 0x444488CC, 0x17172E39,
            -0x3b3b6ca9, -0x5858aa0e, 0x7E7EFC82, 0x3D3D7A47,
            0x6464C8AC, 0x5D5DBAE7, 0x1919322B, 0x7373E695,
            0x6060C0A0, -0x7e7ee668, 0x4F4F9ED1, -0x23235c81,
            0x22224466, 0x2A2A547E, -0x6f6fc455, -0x7777f47d,
            0x46468CCA, -0x111138d7, -0x4747942d, 0x1414283C,
            -0x21215887, 0x5E5EBCE2, 0x0B0B161D, -0x2424528a,
            -0x1f1f24c5, 0x32326456, 0x3A3A744E, 0x0A0A141E,
            0x494992DB, 0x06060C0A, 0x2424486C, 0x5C5CB8E4,
            -0x3d3d60a3, -0x2c2c4292, -0x5353bc11, 0x6262C4A6,
            -0x6e6ec658, -0x6a6ace5c, -0x1b1b2cc9, 0x7979F28B,
            -0x18182ace, -0x373774bd, 0x37376E59, 0x6D6DDAB7,
            -0x7272fe74, -0x2a2a4e9c, 0x4E4E9CD2, -0x5656b620,
            0x6C6CD8B4, 0x5656ACFA, -0xb0b0cf9, -0x151530db,
            0x6565CAAF, 0x7A7AF48E, -0x5151b817, 0x08081018,
            -0x4545902b, 0x7878F088, 0x25254A6F, 0x2E2E5C72,
            0x1C1C3824, -0x5959a80f, -0x4b4b8c39, -0x393968af,
            -0x171734dd, -0x22225e84, 0x7474E89C, 0x1F1F3E21,
            0x4B4B96DD, -0x42429e24, -0x7474f27a, -0x7575f07b,
            0x7070E090, 0x3E3E7C42, -0x4a4a8e3c, 0x6666CCAA,
            0x484890D8, 0x03030605, -0x90908ff, 0x0E0E1C12,
            0x6161C2A3, 0x35356A5F, 0x5757AEF9, -0x46469630,
            -0x7979e86f, -0x3e3e66a8, 0x1D1D3A27, -0x6161d847,
            -0x1e1e26c8, -0x70714ed, -0x6767d44d, 0x11112233,
            0x6969D2BB, -0x26265690, -0x7171f877, -0x6b6bcc59,
            -0x6464d24a, 0x1E1E3C22, -0x7878ea6e, -0x161636e0,
            -0x313178b7, 0x5555AAFF, 0x28285078, -0x20205a86,
            -0x7373fc71, -0x5e5ea608, -0x7676f680, 0x0D0D1A17,
            -0x40409a26, -0x191928cf, 0x424284C6, 0x6868D0B8,
            0x414182C3, -0x6666d650, 0x2D2D5A77, 0x0F0F1E11,
            -0x4f4f8435, 0x5454A8FC, -0x4444922a, 0x16162C3A
        )
        private val AES2 = intArrayOf(
            0x63C6A563, 0x7CF8847C, 0x77EE9977, 0x7BF68D7B,
            -0xd00f20e, 0x6BD6BD6B, 0x6FDEB16F, -0x3a6eab3b,
            0x30605030, 0x01020301, 0x67CEA967, 0x2B567D2B,
            -0x118e602, -0x284a9d29, -0x54b21955, 0x76EC9A76,
            -0x3570ba36, -0x7de0627e, -0x3676bf37, 0x7DFA877D,
            -0x510ea06, 0x59B2EB59, 0x478EC947, -0xf04f410,
            -0x52be1353, -0x2b4c982c, -0x5da0025e, -0x50ba1551,
            -0x63dc4064, -0x5bac085c, 0x72E49672, -0x3f64a440,
            -0x488a3d49, -0x21ee303, -0x6cc2516d, 0x264C6A26,
            0x366C5A36, 0x3F7E413F, -0x80afd09, -0x337cb034,
            0x34685C34, -0x5aae0b5b, -0x1a2ecb1b, -0xe06f70f,
            0x71E29371, -0x27548c28, 0x31625331, 0x152A3F15,
            0x04080C04, -0x386aad39, 0x23466523, -0x3c62a13d,
            0x18302818, -0x69c85e6a, 0x050A0F05, -0x65d04a66,
            0x070E0907, 0x12243612, -0x7fe46480, -0x1d20c21e,
            -0x1432d915, 0x274E6927, -0x4d80324e, 0x75EA9F75,
            0x09121B09, -0x7ce2617d, 0x2C58742C, 0x1A342E1A,
            0x1B362D1B, 0x6EDCB26E, 0x5AB4EE5A, -0x5fa40460,
            0x52A4F652, 0x3B764D3B, -0x29489e2a, -0x4c82314d,
            0x29527B29, -0x1c22c11d, 0x2F5E712F, -0x7bec687c,
            0x53A6F553, -0x2e46972f, 0x00000000, -0x123ed313,
            0x20406020, -0x31ce004, -0x4e86374f, 0x5BB6ED5B,
            0x6AD4BE6A, -0x3472b935, -0x41982642, 0x39724B39,
            0x4A94DE4A, 0x4C98D44C, 0x58B0E858, -0x307ab531,
            -0x2f449430, -0x103ad511, -0x55b01a56, -0x412e905,
            0x4386C543, 0x4D9AD74D, 0x33665533, -0x7aee6b7b,
            0x458ACF45, -0x616ef07, 0x02040602, 0x7FFE817F,
            0x50A0F050, 0x3C78443C, -0x60da4561, -0x57b41c58,
            0x51A2F351, -0x5ca2015d, 0x4080C040, -0x70fa7571,
            -0x6dc0526e, -0x62de4363, 0x38704838, -0xa0efb0b,
            -0x439c2044, -0x49883e4a, -0x25508a26, 0x21426321,
            0x10203010, -0x1ae501, -0xc02f10d, -0x2d40922e,
            -0x327eb333, 0x0C18140C, 0x13263513, -0x133cd014,
            0x5FBEE15F, -0x68ca5d69, 0x4488CC44, 0x172E3917,
            -0x3b6ca83c, -0x58aa0d59, 0x7EFC827E, 0x3D7A473D,
            0x64C8AC64, 0x5DBAE75D, 0x19322B19, 0x73E69573,
            0x60C0A060, -0x7ee6677f, 0x4F9ED14F, -0x235c8024,
            0x22446622, 0x2A547E2A, -0x6fc45470, -0x77f47c78,
            0x468CCA46, -0x1138d612, -0x47942c48, 0x14283C14,
            -0x21588622, 0x5EBCE25E, 0x0B161D0B, -0x24528925,
            -0x1f24c420, 0x32645632, 0x3A744E3A, 0x0A141E0A,
            0x4992DB49, 0x060C0A06, 0x24486C24, 0x5CB8E45C,
            -0x3d60a23e, -0x2c42912d, -0x53bc1054, 0x62C4A662,
            -0x6ec6576f, -0x6ace5b6b, -0x1b2cc81c, 0x79F28B79,
            -0x182acd19, -0x3774bc38, 0x376E5937, 0x6DDAB76D,
            -0x72fe7373, -0x2a4e9b2b, 0x4E9CD24E, -0x56b61f57,
            0x6CD8B46C, 0x56ACFA56, -0xb0cf80c, -0x1530da16,
            0x65CAAF65, 0x7AF48E7A, -0x51b81652, 0x08101808,
            -0x45902a46, 0x78F08878, 0x254A6F25, 0x2E5C722E,
            0x1C38241C, -0x59a80e5a, -0x4b8c384c, -0x3968ae3a,
            -0x1734dc18, -0x225e8323, 0x74E89C74, 0x1F3E211F,
            0x4B96DD4B, -0x429e2343, -0x74f27975, -0x75f07a76,
            0x70E09070, 0x3E7C423E, -0x4a8e3b4b, 0x66CCAA66,
            0x4890D848, 0x03060503, -0x908fe0a, 0x0E1C120E,
            0x61C2A361, 0x356A5F35, 0x57AEF957, -0x46962f47,
            -0x79e86e7a, -0x3e66a73f, 0x1D3A271D, -0x61d84662,
            -0x1e26c71f, -0x714ec08, -0x67d44c68, 0x11223311,
            0x69D2BB69, -0x26568f27, -0x71f87672, -0x6bcc586c,
            -0x64d24965, 0x1E3C221E, -0x78ea6d79, -0x1636df17,
            -0x3178b632, 0x55AAFF55, 0x28507828, -0x205a8521,
            -0x73fc7074, -0x5ea6075f, -0x76f67f77, 0x0D1A170D,
            -0x409a2541, -0x1928ce1a, 0x4284C642, 0x68D0B868,
            0x4182C341, -0x66d64f67, 0x2D5A772D, 0x0F1E110F,
            -0x4f843450, 0x54A8FC54, -0x44922945, 0x162C3A16
        )
        private val AES3 = intArrayOf(
            -0x395a9c9d, -0x77b8384, -0x11668889, -0x9728485,
            -0xf20d0e, -0x29429495, -0x214e9091, -0x6eab3a3b,
            0x60503030, 0x02030101, -0x31569899, 0x567D2B2B,
            -0x18e60102, -0x4a9d2829, 0x4DE6ABAB, -0x1365898a,
            -0x70ba3536, 0x1F9D8282, -0x76bf3637, -0x5788283,
            -0x10ea0506, -0x4d14a6a7, -0x7136b8b9, -0x4f40f10,
            0x41ECADAD, -0x4c982b2c, 0x5FFDA2A2, 0x45EAAFAF,
            0x23BF9C9C, 0x53F7A4A4, -0x1b698d8e, -0x64a43f40,
            0x75C2B7B7, -0x1ee30203, 0x3DAE9393, 0x4C6A2626,
            0x6C5A3636, 0x7E413F3F, -0xafd0809, -0x7cb03334,
            0x685C3434, 0x51F4A5A5, -0x2ecb1a1b, -0x6f70e0f,
            -0x1d6c8e8f, -0x548c2728, 0x62533131, 0x2A3F1515,
            0x080C0404, -0x6aad3839, 0x46652323, -0x62a13c3d,
            0x30281818, 0x37A19696, 0x0A0F0505, 0x2FB59A9A,
            0x0E090707, 0x24361212, 0x1B9B8080, -0x20c21d1e,
            -0x32d91415, 0x4E692727, 0x7FCDB2B2, -0x15608a8b,
            0x121B0909, 0x1D9E8383, 0x58742C2C, 0x342E1A1A,
            0x362D1B1B, -0x234d9192, -0x4b11a5a6, 0x5BFBA0A0,
            -0x5b09adae, 0x764D3B3B, -0x489e292a, 0x7DCEB3B3,
            0x527B2929, -0x22c11c1d, 0x5E712F2F, 0x13978484,
            -0x590aacad, -0x46972e2f, 0x00000000, -0x3ed31213,
            0x40602020, -0x1ce00304, 0x79C8B1B1, -0x4912a4a5,
            -0x2b419596, -0x72b93435, 0x67D9BEBE, 0x724B3939,
            -0x6b21b5b6, -0x672bb3b4, -0x4f17a7a8, -0x7ab53031,
            -0x44942f30, -0x3ad51011, 0x4FE5AAAA, -0x12e90405,
            -0x793abcbd, -0x6528b2b3, 0x66553333, 0x11948585,
            -0x7530babb, -0x16ef0607, 0x04060202, -0x17e8081,
            -0x5f0fafb0, 0x78443C3C, 0x25BA9F9F, 0x4BE3A8A8,
            -0x5d0caeaf, 0x5DFEA3A3, -0x7f3fbfc0, 0x058A8F8F,
            0x3FAD9292, 0x21BC9D9D, 0x70483838, -0xefb0a0b,
            0x63DFBCBC, 0x77C1B6B6, -0x508a2526, 0x42632121,
            0x20301010, -0x1ae50001, -0x2f10c0d, -0x40922d2e,
            -0x7eb33233, 0x18140C0C, 0x26351313, -0x3cd01314,
            -0x411ea0a1, 0x35A29797, -0x7733bbbc, 0x2E391717,
            -0x6ca83b3c, 0x55F2A7A7, -0x37d8182, 0x7A473D3D,
            -0x37539b9c, -0x4518a2a3, 0x322B1919, -0x196a8c8d,
            -0x3f5f9fa0, 0x19988181, -0x612eb0b1, -0x5c802324,
            0x44662222, 0x547E2A2A, 0x3BAB9090, 0x0B838888,
            -0x7335b9ba, -0x38d61112, 0x6BD3B8B8, 0x283C1414,
            -0x58862122, -0x431da1a2, 0x161D0B0B, -0x52892425,
            -0x24c41f20, 0x64563232, 0x744E3A3A, 0x141E0A0A,
            -0x6d24b6b7, 0x0C0A0606, 0x486C2424, -0x471ba3a4,
            -0x60a23d3e, -0x42912c2d, 0x43EFACAC, -0x3b599d9e,
            0x39A89191, 0x31A49595, -0x2cc81b1c, -0xd748687,
            -0x2acd1819, -0x74bc3738, 0x6E593737, -0x25489293,
            0x018C8D8D, -0x4e9b2a2b, -0x632db1b2, 0x49E0A9A9,
            -0x274b9394, -0x5305a9aa, -0xcf80b0c, -0x30da1516,
            -0x35509a9b, -0xb718586, 0x47E9AEAE, 0x10180808,
            0x6FD5BABA, -0xf778788, 0x4A6F2525, 0x5C722E2E,
            0x38241C1C, 0x57F1A6A6, 0x73C7B4B4, -0x68ae393a,
            -0x34dc1718, -0x5e832223, -0x17638b8c, 0x3E211F1F,
            -0x6922b4b5, 0x61DCBDBD, 0x0D868B8B, 0x0F858A8A,
            -0x1f6f8f90, 0x7C423E3E, 0x71C4B5B5, -0x3355999a,
            -0x6f27b7b8, 0x06050303, -0x8fe090a, 0x1C120E0E,
            -0x3d5c9e9f, 0x6A5F3535, -0x5106a8a9, 0x69D0B9B9,
            0x17918686, -0x66a73e3f, 0x3A271D1D, 0x27B99E9E,
            -0x26c71e1f, -0x14ec0708, 0x2BB39898, 0x22331111,
            -0x2d449697, -0x568f2627, 0x07898E8E, 0x33A79494,
            0x2DB69B9B, 0x3C221E1E, 0x15928787, -0x36df1617,
            -0x78b63132, -0x5500aaab, 0x50782828, -0x5a852021,
            0x038F8C8C, 0x59F8A1A1, 0x09808989, 0x1A170D0D,
            0x65DABFBF, -0x28ce191a, -0x7b39bdbe, -0x2f479798,
            -0x7d3cbebf, 0x29B09999, 0x5A772D2D, 0x1E110F0F,
            0x7BCBB0B0, -0x5703abac, 0x6DD6BBBB, 0x2C3A1616
        )
    }
}
