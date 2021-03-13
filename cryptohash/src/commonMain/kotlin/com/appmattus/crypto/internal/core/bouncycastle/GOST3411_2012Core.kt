/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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

package com.appmattus.crypto.internal.core.bouncycastle

import com.appmattus.crypto.Digest
import kotlin.experimental.xor

/**
 * General Information
 *
 *
 * 1. GOST R 34.11-2012 was developed by the Center for Information
 * Protection and Special Communications of the Federal Security
 * Service of the Russian Federation with participation of the Open
 * joint-stock company "Information Technologies and Communication
 * Systems" (InfoTeCS JSC).
 *
 *
 * 2. GOST R 34.11-2012 was approved and introduced by Decree #216 of
 * the Federal Agency on Technical Regulating and Metrology on
 * 07.08.2012.
 *
 *
 * 3. GOST R 34.11-2012 intended to replace GOST R 34.11-94 national
 * standard of Russian Federation.
 *
 *
 * Reference Implementation and Description can be found at: https://www.streebog.net/
 * RFC: https://tools.ietf.org/html/rfc6986
 */

/**
 * Base class for GOST3411-2012 256-bit and GOST3411-2012 512-bit digests.
 */
@Suppress("ClassName", "TooManyFunctions", "MagicNumber", "LargeClass")
internal abstract class GOST3411_2012Core<D : GOST3411_2012Core<D>>(iv: ByteArray) : Digest<D> {
    private val iv = ByteArray(64)
    private val n = ByteArray(64)
    private val sigma = ByteArray(64)
    private val ki = ByteArray(64)
    private val m = ByteArray(64)
    private val h = ByteArray(64)

    // Temporary buffers
    private val tmp = ByteArray(64)
    private val block = ByteArray(64)
    private var bOff = 64
    val byteLength: Int
        get() = 64

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun digest(): ByteArray {
        val result = ByteArray(digestLength)
        doFinal(result, 0)
        reset()
        return result
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override fun update(input: Byte) {
        block[--bOff] = input
        if (bOff == 0) {
            gN(h, n, block)
            addMod512(n, 512)
            addMod512(sigma, block)
            bOff = 64
        }
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var inOff = offset
        var len = length
        while (bOff != 64 && len > 0) {
            update(input[inOff++])
            len--
        }
        while (len >= 64) {
            input.copyInto(tmp, 0, inOff, inOff + 64)
            reverse(tmp, block)
            gN(h, n, block)
            addMod512(n, 512)
            addMod512(sigma, block)
            len -= 64
            inOff += 64
        }
        while (len > 0) {
            update(input[inOff++])
            len--
        }
    }

    open fun doFinal(out: ByteArray, outOff: Int): Int {
        val lenM = 64 - bOff

        // At this point it is certain that lenM is smaller than 64
        for (i in 0 until 64 - lenM) {
            m[i] = 0
        }
        m[63 - lenM] = 1
        if (bOff != 64) {
            block.copyInto(m, 64 - lenM, bOff, bOff + lenM)
        }
        gN(h, n, m)
        addMod512(n, lenM * 8)
        addMod512(sigma, m)
        gN(h, Zero, n)
        gN(h, Zero, sigma)
        reverse(h, tmp)
        tmp.copyInto(out, outOff, 0, 64)
        reset()
        return 64
    }

    override fun reset() {
        bOff = 64
        n.fill(0.toByte())
        sigma.fill(0.toByte())
        iv.copyInto(h, 0, 0, 64)
        block.fill(0.toByte())
    }

    @Suppress("LongMethod")
    private fun f(v: ByteArray) {
        val res = LongArray(8)
        var r: Long = 0
        r = r xor T[0][v[56].toInt() and 0xFF]
        r = r xor T[1][v[48].toInt() and 0xFF]
        r = r xor T[2][v[40].toInt() and 0xFF]
        r = r xor T[3][v[32].toInt() and 0xFF]
        r = r xor T[4][v[24].toInt() and 0xFF]
        r = r xor T[5][v[16].toInt() and 0xFF]
        r = r xor T[6][v[8].toInt() and 0xFF]
        r = r xor T[7][v[0].toInt() and 0xFF]
        res[0] = r
        r = 0
        r = r xor T[0][v[57].toInt() and 0xFF]
        r = r xor T[1][v[49].toInt() and 0xFF]
        r = r xor T[2][v[41].toInt() and 0xFF]
        r = r xor T[3][v[33].toInt() and 0xFF]
        r = r xor T[4][v[25].toInt() and 0xFF]
        r = r xor T[5][v[17].toInt() and 0xFF]
        r = r xor T[6][v[9].toInt() and 0xFF]
        r = r xor T[7][v[1].toInt() and 0xFF]
        res[1] = r
        r = 0
        r = r xor T[0][v[58].toInt() and 0xFF]
        r = r xor T[1][v[50].toInt() and 0xFF]
        r = r xor T[2][v[42].toInt() and 0xFF]
        r = r xor T[3][v[34].toInt() and 0xFF]
        r = r xor T[4][v[26].toInt() and 0xFF]
        r = r xor T[5][v[18].toInt() and 0xFF]
        r = r xor T[6][v[10].toInt() and 0xFF]
        r = r xor T[7][v[2].toInt() and 0xFF]
        res[2] = r
        r = 0
        r = r xor T[0][v[59].toInt() and 0xFF]
        r = r xor T[1][v[51].toInt() and 0xFF]
        r = r xor T[2][v[43].toInt() and 0xFF]
        r = r xor T[3][v[35].toInt() and 0xFF]
        r = r xor T[4][v[27].toInt() and 0xFF]
        r = r xor T[5][v[19].toInt() and 0xFF]
        r = r xor T[6][v[11].toInt() and 0xFF]
        r = r xor T[7][v[3].toInt() and 0xFF]
        res[3] = r
        r = 0
        r = r xor T[0][v[60].toInt() and 0xFF]
        r = r xor T[1][v[52].toInt() and 0xFF]
        r = r xor T[2][v[44].toInt() and 0xFF]
        r = r xor T[3][v[36].toInt() and 0xFF]
        r = r xor T[4][v[28].toInt() and 0xFF]
        r = r xor T[5][v[20].toInt() and 0xFF]
        r = r xor T[6][v[12].toInt() and 0xFF]
        r = r xor T[7][v[4].toInt() and 0xFF]
        res[4] = r
        r = 0
        r = r xor T[0][v[61].toInt() and 0xFF]
        r = r xor T[1][v[53].toInt() and 0xFF]
        r = r xor T[2][v[45].toInt() and 0xFF]
        r = r xor T[3][v[37].toInt() and 0xFF]
        r = r xor T[4][v[29].toInt() and 0xFF]
        r = r xor T[5][v[21].toInt() and 0xFF]
        r = r xor T[6][v[13].toInt() and 0xFF]
        r = r xor T[7][v[5].toInt() and 0xFF]
        res[5] = r
        r = 0
        r = r xor T[0][v[62].toInt() and 0xFF]
        r = r xor T[1][v[54].toInt() and 0xFF]
        r = r xor T[2][v[46].toInt() and 0xFF]
        r = r xor T[3][v[38].toInt() and 0xFF]
        r = r xor T[4][v[30].toInt() and 0xFF]
        r = r xor T[5][v[22].toInt() and 0xFF]
        r = r xor T[6][v[14].toInt() and 0xFF]
        r = r xor T[7][v[6].toInt() and 0xFF]
        res[6] = r
        r = 0
        r = r xor T[0][v[63].toInt() and 0xFF]
        r = r xor T[1][v[55].toInt() and 0xFF]
        r = r xor T[2][v[47].toInt() and 0xFF]
        r = r xor T[3][v[39].toInt() and 0xFF]
        r = r xor T[4][v[31].toInt() and 0xFF]
        r = r xor T[5][v[23].toInt() and 0xFF]
        r = r xor T[6][v[15].toInt() and 0xFF]
        r = r xor T[7][v[7].toInt() and 0xFF]
        res[7] = r
        r = res[0]
        v[7] = (r shr 56).toByte()
        v[6] = (r shr 48).toByte()
        v[5] = (r shr 40).toByte()
        v[4] = (r shr 32).toByte()
        v[3] = (r shr 24).toByte()
        v[2] = (r shr 16).toByte()
        v[1] = (r shr 8).toByte()
        v[0] = r.toByte()
        r = res[1]
        v[15] = (r shr 56).toByte()
        v[14] = (r shr 48).toByte()
        v[13] = (r shr 40).toByte()
        v[12] = (r shr 32).toByte()
        v[11] = (r shr 24).toByte()
        v[10] = (r shr 16).toByte()
        v[9] = (r shr 8).toByte()
        v[8] = r.toByte()
        r = res[2]
        v[23] = (r shr 56).toByte()
        v[22] = (r shr 48).toByte()
        v[21] = (r shr 40).toByte()
        v[20] = (r shr 32).toByte()
        v[19] = (r shr 24).toByte()
        v[18] = (r shr 16).toByte()
        v[17] = (r shr 8).toByte()
        v[16] = r.toByte()
        r = res[3]
        v[31] = (r shr 56).toByte()
        v[30] = (r shr 48).toByte()
        v[29] = (r shr 40).toByte()
        v[28] = (r shr 32).toByte()
        v[27] = (r shr 24).toByte()
        v[26] = (r shr 16).toByte()
        v[25] = (r shr 8).toByte()
        v[24] = r.toByte()
        r = res[4]
        v[39] = (r shr 56).toByte()
        v[38] = (r shr 48).toByte()
        v[37] = (r shr 40).toByte()
        v[36] = (r shr 32).toByte()
        v[35] = (r shr 24).toByte()
        v[34] = (r shr 16).toByte()
        v[33] = (r shr 8).toByte()
        v[32] = r.toByte()
        r = res[5]
        v[47] = (r shr 56).toByte()
        v[46] = (r shr 48).toByte()
        v[45] = (r shr 40).toByte()
        v[44] = (r shr 32).toByte()
        v[43] = (r shr 24).toByte()
        v[42] = (r shr 16).toByte()
        v[41] = (r shr 8).toByte()
        v[40] = r.toByte()
        r = res[6]
        v[55] = (r shr 56).toByte()
        v[54] = (r shr 48).toByte()
        v[53] = (r shr 40).toByte()
        v[52] = (r shr 32).toByte()
        v[51] = (r shr 24).toByte()
        v[50] = (r shr 16).toByte()
        v[49] = (r shr 8).toByte()
        v[48] = r.toByte()
        r = res[7]
        v[63] = (r shr 56).toByte()
        v[62] = (r shr 48).toByte()
        v[61] = (r shr 40).toByte()
        v[60] = (r shr 32).toByte()
        v[59] = (r shr 24).toByte()
        v[58] = (r shr 16).toByte()
        v[57] = (r shr 8).toByte()
        v[56] = r.toByte()
    }

    private fun xor512(a: ByteArray, b: ByteArray) {
        for (i in 0..63) {
            a[i] = a[i] xor b[i]
        }
    }

    private fun e(k: ByteArray, m: ByteArray) {
        k.copyInto(ki, 0, 0, 64)
        xor512(k, m)
        f(k)
        for (i in 0..10) {
            xor512(ki, C[i])
            f(ki)
            xor512(k, ki)
            f(k)
        }
        xor512(ki, C[11])
        f(ki)
        xor512(k, ki)
    }

    private fun gN(h: ByteArray, n: ByteArray, m: ByteArray) {
        h.copyInto(tmp, 0, 0, 64)

        xor512(h, n)
        f(h)
        e(h, m)
        xor512(h, tmp)
        xor512(h, m)
    }

    private fun addMod512(a: ByteArray, num: Int) {
        var c: Int
        c = (a[63].toInt() and 0xFF) + (num and 0xFF)
        a[63] = c.toByte()
        c = (a[62].toInt() and 0xFF) + (num shr 8 and 0xFF) + (c shr 8)
        a[62] = c.toByte()
        var i = 61
        while (i >= 0 && c > 0) {
            c = (a[i].toInt() and 0xFF) + (c shr 8)
            a[i] = c.toByte()
            --i
        }
    }

    private fun addMod512(a: ByteArray, b: ByteArray) {
        var c = 0
        var i = 63
        while (i >= 0) {
            c = (a[i].toInt() and 0xFF) + (b[i].toInt() and 0xFF) + (c shr 8)
            a[i] = c.toByte()
            --i
        }
    }

    private fun reverse(src: ByteArray, dst: ByteArray) {
        val len = src.size
        for (i in 0 until len) {
            dst[len - 1 - i] = src[i]
        }
    }

    companion object {
        private val C = arrayOf(
            byteArrayOf(
                0xb1.toByte(), 0x08.toByte(), 0x5b.toByte(), 0xda.toByte(), 0x1e.toByte(), 0xca.toByte(), 0xda.toByte(), 0xe9.toByte(),
                0xeb.toByte(), 0xcb.toByte(), 0x2f.toByte(), 0x81.toByte(), 0xc0.toByte(), 0x65.toByte(), 0x7c.toByte(), 0x1f.toByte(),
                0x2f.toByte(), 0x6a.toByte(), 0x76.toByte(), 0x43.toByte(), 0x2e.toByte(), 0x45.toByte(), 0xd0.toByte(), 0x16.toByte(),
                0x71.toByte(), 0x4e.toByte(), 0xb8.toByte(), 0x8d.toByte(), 0x75.toByte(), 0x85.toByte(), 0xc4.toByte(), 0xfc.toByte(),
                0x4b.toByte(), 0x7c.toByte(), 0xe0.toByte(), 0x91.toByte(), 0x92.toByte(), 0x67.toByte(), 0x69.toByte(), 0x01.toByte(),
                0xa2.toByte(), 0x42.toByte(), 0x2a.toByte(), 0x08.toByte(), 0xa4.toByte(), 0x60.toByte(), 0xd3.toByte(), 0x15.toByte(),
                0x05.toByte(), 0x76.toByte(), 0x74.toByte(), 0x36.toByte(), 0xcc.toByte(), 0x74.toByte(), 0x4d.toByte(), 0x23.toByte(),
                0xdd.toByte(), 0x80.toByte(), 0x65.toByte(), 0x59.toByte(), 0xf2.toByte(), 0xa6.toByte(), 0x45.toByte(), 0x07.toByte()
            ), byteArrayOf(
                0x6f.toByte(), 0xa3.toByte(), 0xb5.toByte(), 0x8a.toByte(), 0xa9.toByte(), 0x9d.toByte(), 0x2f.toByte(), 0x1a.toByte(),
                0x4f.toByte(), 0xe3.toByte(), 0x9d.toByte(), 0x46.toByte(), 0x0f.toByte(), 0x70.toByte(), 0xb5.toByte(), 0xd7.toByte(),
                0xf3.toByte(), 0xfe.toByte(), 0xea.toByte(), 0x72.toByte(), 0x0a.toByte(), 0x23.toByte(), 0x2b.toByte(), 0x98.toByte(),
                0x61.toByte(), 0xd5.toByte(), 0x5e.toByte(), 0x0f.toByte(), 0x16.toByte(), 0xb5.toByte(), 0x01.toByte(), 0x31.toByte(),
                0x9a.toByte(), 0xb5.toByte(), 0x17.toByte(), 0x6b.toByte(), 0x12.toByte(), 0xd6.toByte(), 0x99.toByte(), 0x58.toByte(),
                0x5c.toByte(), 0xb5.toByte(), 0x61.toByte(), 0xc2.toByte(), 0xdb.toByte(), 0x0a.toByte(), 0xa7.toByte(), 0xca.toByte(),
                0x55.toByte(), 0xdd.toByte(), 0xa2.toByte(), 0x1b.toByte(), 0xd7.toByte(), 0xcb.toByte(), 0xcd.toByte(), 0x56.toByte(),
                0xe6.toByte(), 0x79.toByte(), 0x04.toByte(), 0x70.toByte(), 0x21.toByte(), 0xb1.toByte(), 0x9b.toByte(), 0xb7.toByte()
            ), byteArrayOf(
                0xf5.toByte(), 0x74.toByte(), 0xdc.toByte(), 0xac.toByte(), 0x2b.toByte(), 0xce.toByte(), 0x2f.toByte(), 0xc7.toByte(),
                0x0a.toByte(), 0x39.toByte(), 0xfc.toByte(), 0x28.toByte(), 0x6a.toByte(), 0x3d.toByte(), 0x84.toByte(), 0x35.toByte(),
                0x06.toByte(), 0xf1.toByte(), 0x5e.toByte(), 0x5f.toByte(), 0x52.toByte(), 0x9c.toByte(), 0x1f.toByte(), 0x8b.toByte(),
                0xf2.toByte(), 0xea.toByte(), 0x75.toByte(), 0x14.toByte(), 0xb1.toByte(), 0x29.toByte(), 0x7b.toByte(), 0x7b.toByte(),
                0xd3.toByte(), 0xe2.toByte(), 0x0f.toByte(), 0xe4.toByte(), 0x90.toByte(), 0x35.toByte(), 0x9e.toByte(), 0xb1.toByte(),
                0xc1.toByte(), 0xc9.toByte(), 0x3a.toByte(), 0x37.toByte(), 0x60.toByte(), 0x62.toByte(), 0xdb.toByte(), 0x09.toByte(),
                0xc2.toByte(), 0xb6.toByte(), 0xf4.toByte(), 0x43.toByte(), 0x86.toByte(), 0x7a.toByte(), 0xdb.toByte(), 0x31.toByte(),
                0x99.toByte(), 0x1e.toByte(), 0x96.toByte(), 0xf5.toByte(), 0x0a.toByte(), 0xba.toByte(), 0x0a.toByte(), 0xb2.toByte()
            ), byteArrayOf(
                0xef.toByte(), 0x1f.toByte(), 0xdf.toByte(), 0xb3.toByte(), 0xe8.toByte(), 0x15.toByte(), 0x66.toByte(), 0xd2.toByte(),
                0xf9.toByte(), 0x48.toByte(), 0xe1.toByte(), 0xa0.toByte(), 0x5d.toByte(), 0x71.toByte(), 0xe4.toByte(), 0xdd.toByte(),
                0x48.toByte(), 0x8e.toByte(), 0x85.toByte(), 0x7e.toByte(), 0x33.toByte(), 0x5c.toByte(), 0x3c.toByte(), 0x7d.toByte(),
                0x9d.toByte(), 0x72.toByte(), 0x1c.toByte(), 0xad.toByte(), 0x68.toByte(), 0x5e.toByte(), 0x35.toByte(), 0x3f.toByte(),
                0xa9.toByte(), 0xd7.toByte(), 0x2c.toByte(), 0x82.toByte(), 0xed.toByte(), 0x03.toByte(), 0xd6.toByte(), 0x75.toByte(),
                0xd8.toByte(), 0xb7.toByte(), 0x13.toByte(), 0x33.toByte(), 0x93.toByte(), 0x52.toByte(), 0x03.toByte(), 0xbe.toByte(),
                0x34.toByte(), 0x53.toByte(), 0xea.toByte(), 0xa1.toByte(), 0x93.toByte(), 0xe8.toByte(), 0x37.toByte(), 0xf1.toByte(),
                0x22.toByte(), 0x0c.toByte(), 0xbe.toByte(), 0xbc.toByte(), 0x84.toByte(), 0xe3.toByte(), 0xd1.toByte(), 0x2e.toByte()
            ), byteArrayOf(
                0x4b.toByte(), 0xea.toByte(), 0x6b.toByte(), 0xac.toByte(), 0xad.toByte(), 0x47.toByte(), 0x47.toByte(), 0x99.toByte(),
                0x9a.toByte(), 0x3f.toByte(), 0x41.toByte(), 0x0c.toByte(), 0x6c.toByte(), 0xa9.toByte(), 0x23.toByte(), 0x63.toByte(),
                0x7f.toByte(), 0x15.toByte(), 0x1c.toByte(), 0x1f.toByte(), 0x16.toByte(), 0x86.toByte(), 0x10.toByte(), 0x4a.toByte(),
                0x35.toByte(), 0x9e.toByte(), 0x35.toByte(), 0xd7.toByte(), 0x80.toByte(), 0x0f.toByte(), 0xff.toByte(), 0xbd.toByte(),
                0xbf.toByte(), 0xcd.toByte(), 0x17.toByte(), 0x47.toByte(), 0x25.toByte(), 0x3a.toByte(), 0xf5.toByte(), 0xa3.toByte(),
                0xdf.toByte(), 0xff.toByte(), 0x00.toByte(), 0xb7.toByte(), 0x23.toByte(), 0x27.toByte(), 0x1a.toByte(), 0x16.toByte(),
                0x7a.toByte(), 0x56.toByte(), 0xa2.toByte(), 0x7e.toByte(), 0xa9.toByte(), 0xea.toByte(), 0x63.toByte(), 0xf5.toByte(),
                0x60.toByte(), 0x17.toByte(), 0x58.toByte(), 0xfd.toByte(), 0x7c.toByte(), 0x6c.toByte(), 0xfe.toByte(), 0x57.toByte()
            ), byteArrayOf(
                0xae.toByte(), 0x4f.toByte(), 0xae.toByte(), 0xae.toByte(), 0x1d.toByte(), 0x3a.toByte(), 0xd3.toByte(), 0xd9.toByte(),
                0x6f.toByte(), 0xa4.toByte(), 0xc3.toByte(), 0x3b.toByte(), 0x7a.toByte(), 0x30.toByte(), 0x39.toByte(), 0xc0.toByte(),
                0x2d.toByte(), 0x66.toByte(), 0xc4.toByte(), 0xf9.toByte(), 0x51.toByte(), 0x42.toByte(), 0xa4.toByte(), 0x6c.toByte(),
                0x18.toByte(), 0x7f.toByte(), 0x9a.toByte(), 0xb4.toByte(), 0x9a.toByte(), 0xf0.toByte(), 0x8e.toByte(), 0xc6.toByte(),
                0xcf.toByte(), 0xfa.toByte(), 0xa6.toByte(), 0xb7.toByte(), 0x1c.toByte(), 0x9a.toByte(), 0xb7.toByte(), 0xb4.toByte(),
                0x0a.toByte(), 0xf2.toByte(), 0x1f.toByte(), 0x66.toByte(), 0xc2.toByte(), 0xbe.toByte(), 0xc6.toByte(), 0xb6.toByte(),
                0xbf.toByte(), 0x71.toByte(), 0xc5.toByte(), 0x72.toByte(), 0x36.toByte(), 0x90.toByte(), 0x4f.toByte(), 0x35.toByte(),
                0xfa.toByte(), 0x68.toByte(), 0x40.toByte(), 0x7a.toByte(), 0x46.toByte(), 0x64.toByte(), 0x7d.toByte(), 0x6e.toByte()
            ), byteArrayOf(
                0xf4.toByte(), 0xc7.toByte(), 0x0e.toByte(), 0x16.toByte(), 0xee.toByte(), 0xaa.toByte(), 0xc5.toByte(), 0xec.toByte(),
                0x51.toByte(), 0xac.toByte(), 0x86.toByte(), 0xfe.toByte(), 0xbf.toByte(), 0x24.toByte(), 0x09.toByte(), 0x54.toByte(),
                0x39.toByte(), 0x9e.toByte(), 0xc6.toByte(), 0xc7.toByte(), 0xe6.toByte(), 0xbf.toByte(), 0x87.toByte(), 0xc9.toByte(),
                0xd3.toByte(), 0x47.toByte(), 0x3e.toByte(), 0x33.toByte(), 0x19.toByte(), 0x7a.toByte(), 0x93.toByte(), 0xc9.toByte(),
                0x09.toByte(), 0x92.toByte(), 0xab.toByte(), 0xc5.toByte(), 0x2d.toByte(), 0x82.toByte(), 0x2c.toByte(), 0x37.toByte(),
                0x06.toByte(), 0x47.toByte(), 0x69.toByte(), 0x83.toByte(), 0x28.toByte(), 0x4a.toByte(), 0x05.toByte(), 0x04.toByte(),
                0x35.toByte(), 0x17.toByte(), 0x45.toByte(), 0x4c.toByte(), 0xa2.toByte(), 0x3c.toByte(), 0x4a.toByte(), 0xf3.toByte(),
                0x88.toByte(), 0x86.toByte(), 0x56.toByte(), 0x4d.toByte(), 0x3a.toByte(), 0x14.toByte(), 0xd4.toByte(), 0x93.toByte()
            ), byteArrayOf(
                0x9b.toByte(), 0x1f.toByte(), 0x5b.toByte(), 0x42.toByte(), 0x4d.toByte(), 0x93.toByte(), 0xc9.toByte(), 0xa7.toByte(),
                0x03.toByte(), 0xe7.toByte(), 0xaa.toByte(), 0x02.toByte(), 0x0c.toByte(), 0x6e.toByte(), 0x41.toByte(), 0x41.toByte(),
                0x4e.toByte(), 0xb7.toByte(), 0xf8.toByte(), 0x71.toByte(), 0x9c.toByte(), 0x36.toByte(), 0xde.toByte(), 0x1e.toByte(),
                0x89.toByte(), 0xb4.toByte(), 0x44.toByte(), 0x3b.toByte(), 0x4d.toByte(), 0xdb.toByte(), 0xc4.toByte(), 0x9a.toByte(),
                0xf4.toByte(), 0x89.toByte(), 0x2b.toByte(), 0xcb.toByte(), 0x92.toByte(), 0x9b.toByte(), 0x06.toByte(), 0x90.toByte(),
                0x69.toByte(), 0xd1.toByte(), 0x8d.toByte(), 0x2b.toByte(), 0xd1.toByte(), 0xa5.toByte(), 0xc4.toByte(), 0x2f.toByte(),
                0x36.toByte(), 0xac.toByte(), 0xc2.toByte(), 0x35.toByte(), 0x59.toByte(), 0x51.toByte(), 0xa8.toByte(), 0xd9.toByte(),
                0xa4.toByte(), 0x7f.toByte(), 0x0d.toByte(), 0xd4.toByte(), 0xbf.toByte(), 0x02.toByte(), 0xe7.toByte(), 0x1e.toByte()
            ), byteArrayOf(
                0x37.toByte(), 0x8f.toByte(), 0x5a.toByte(), 0x54.toByte(), 0x16.toByte(), 0x31.toByte(), 0x22.toByte(), 0x9b.toByte(),
                0x94.toByte(), 0x4c.toByte(), 0x9a.toByte(), 0xd8.toByte(), 0xec.toByte(), 0x16.toByte(), 0x5f.toByte(), 0xde.toByte(),
                0x3a.toByte(), 0x7d.toByte(), 0x3a.toByte(), 0x1b.toByte(), 0x25.toByte(), 0x89.toByte(), 0x42.toByte(), 0x24.toByte(),
                0x3c.toByte(), 0xd9.toByte(), 0x55.toByte(), 0xb7.toByte(), 0xe0.toByte(), 0x0d.toByte(), 0x09.toByte(), 0x84.toByte(),
                0x80.toByte(), 0x0a.toByte(), 0x44.toByte(), 0x0b.toByte(), 0xdb.toByte(), 0xb2.toByte(), 0xce.toByte(), 0xb1.toByte(),
                0x7b.toByte(), 0x2b.toByte(), 0x8a.toByte(), 0x9a.toByte(), 0xa6.toByte(), 0x07.toByte(), 0x9c.toByte(), 0x54.toByte(),
                0x0e.toByte(), 0x38.toByte(), 0xdc.toByte(), 0x92.toByte(), 0xcb.toByte(), 0x1f.toByte(), 0x2a.toByte(), 0x60.toByte(),
                0x72.toByte(), 0x61.toByte(), 0x44.toByte(), 0x51.toByte(), 0x83.toByte(), 0x23.toByte(), 0x5a.toByte(), 0xdb.toByte()
            ), byteArrayOf(
                0xab.toByte(), 0xbe.toByte(), 0xde.toByte(), 0xa6.toByte(), 0x80.toByte(), 0x05.toByte(), 0x6f.toByte(), 0x52.toByte(),
                0x38.toByte(), 0x2a.toByte(), 0xe5.toByte(), 0x48.toByte(), 0xb2.toByte(), 0xe4.toByte(), 0xf3.toByte(), 0xf3.toByte(),
                0x89.toByte(), 0x41.toByte(), 0xe7.toByte(), 0x1c.toByte(), 0xff.toByte(), 0x8a.toByte(), 0x78.toByte(), 0xdb.toByte(),
                0x1f.toByte(), 0xff.toByte(), 0xe1.toByte(), 0x8a.toByte(), 0x1b.toByte(), 0x33.toByte(), 0x61.toByte(), 0x03.toByte(),
                0x9f.toByte(), 0xe7.toByte(), 0x67.toByte(), 0x02.toByte(), 0xaf.toByte(), 0x69.toByte(), 0x33.toByte(), 0x4b.toByte(),
                0x7a.toByte(), 0x1e.toByte(), 0x6c.toByte(), 0x30.toByte(), 0x3b.toByte(), 0x76.toByte(), 0x52.toByte(), 0xf4.toByte(),
                0x36.toByte(), 0x98.toByte(), 0xfa.toByte(), 0xd1.toByte(), 0x15.toByte(), 0x3b.toByte(), 0xb6.toByte(), 0xc3.toByte(),
                0x74.toByte(), 0xb4.toByte(), 0xc7.toByte(), 0xfb.toByte(), 0x98.toByte(), 0x45.toByte(), 0x9c.toByte(), 0xed.toByte()
            ), byteArrayOf(
                0x7b.toByte(), 0xcd.toByte(), 0x9e.toByte(), 0xd0.toByte(), 0xef.toByte(), 0xc8.toByte(), 0x89.toByte(), 0xfb.toByte(),
                0x30.toByte(), 0x02.toByte(), 0xc6.toByte(), 0xcd.toByte(), 0x63.toByte(), 0x5a.toByte(), 0xfe.toByte(), 0x94.toByte(),
                0xd8.toByte(), 0xfa.toByte(), 0x6b.toByte(), 0xbb.toByte(), 0xeb.toByte(), 0xab.toByte(), 0x07.toByte(), 0x61.toByte(),
                0x20.toByte(), 0x01.toByte(), 0x80.toByte(), 0x21.toByte(), 0x14.toByte(), 0x84.toByte(), 0x66.toByte(), 0x79.toByte(),
                0x8a.toByte(), 0x1d.toByte(), 0x71.toByte(), 0xef.toByte(), 0xea.toByte(), 0x48.toByte(), 0xb9.toByte(), 0xca.toByte(),
                0xef.toByte(), 0xba.toByte(), 0xcd.toByte(), 0x1d.toByte(), 0x7d.toByte(), 0x47.toByte(), 0x6e.toByte(), 0x98.toByte(),
                0xde.toByte(), 0xa2.toByte(), 0x59.toByte(), 0x4a.toByte(), 0xc0.toByte(), 0x6f.toByte(), 0xd8.toByte(), 0x5d.toByte(),
                0x6b.toByte(), 0xca.toByte(), 0xa4.toByte(), 0xcd.toByte(), 0x81.toByte(), 0xf3.toByte(), 0x2d.toByte(), 0x1b.toByte()
            ), byteArrayOf(
                0x37.toByte(), 0x8e.toByte(), 0xe7.toByte(), 0x67.toByte(), 0xf1.toByte(), 0x16.toByte(), 0x31.toByte(), 0xba.toByte(),
                0xd2.toByte(), 0x13.toByte(), 0x80.toByte(), 0xb0.toByte(), 0x04.toByte(), 0x49.toByte(), 0xb1.toByte(), 0x7a.toByte(),
                0xcd.toByte(), 0xa4.toByte(), 0x3c.toByte(), 0x32.toByte(), 0xbc.toByte(), 0xdf.toByte(), 0x1d.toByte(), 0x77.toByte(),
                0xf8.toByte(), 0x20.toByte(), 0x12.toByte(), 0xd4.toByte(), 0x30.toByte(), 0x21.toByte(), 0x9f.toByte(), 0x9b.toByte(),
                0x5d.toByte(), 0x80.toByte(), 0xef.toByte(), 0x9d.toByte(), 0x18.toByte(), 0x91.toByte(), 0xcc.toByte(), 0x86.toByte(),
                0xe7.toByte(), 0x1d.toByte(), 0xa4.toByte(), 0xaa.toByte(), 0x88.toByte(), 0xe1.toByte(), 0x28.toByte(), 0x52.toByte(),
                0xfa.toByte(), 0xf4.toByte(), 0x17.toByte(), 0xd5.toByte(), 0xd9.toByte(), 0xb2.toByte(), 0x1b.toByte(), 0x99.toByte(),
                0x48.toByte(), 0xbc.toByte(), 0x92.toByte(), 0x4a.toByte(), 0xf1.toByte(), 0x1b.toByte(), 0xd7.toByte(), 0x20.toByte()
            )
        )
        private val Zero = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        private val T = arrayOf(
            longArrayOf(
                -0x190781a3a48ee030L, 0x258377800924FA16L, -0x37b61f817ad15b58L, 0x5B4686A18F06C16AL,
                0x0B32E9A2D77B416EL, -0x5425c85b987ea39aL, -0x9e86957e597998aL, -0xa23f48f9c6e6ab5L,
                0x4862F38DB7E64BF1L, -0xa39d6597427a3bL, -0x347d82590328a86bL, 0x66D36DAF69B9F089L,
                0x356C9F74483D83B0L, 0x7CBCECB1238C99A1L, 0x36A702AC31C4708DL, -0x6149572fd043202aL,
                -0x74e605ae1a4c51c9L, -0x63304abf75ed82f5L, -0x43f3874af7df70a6L, -0x1acc1c7bdd771313L,
                -0x313d382c883ea02eL, -0x1387e849afa2f0a2L, -0x46b33d3f7cc978e3L, -0x73dfa24b34f4fb53L,
                0x763C855B28A0892FL, 0x588D1B79F6FF3257L, 0x3FECF69E4311933EL, 0x0FC0D39F803A18C9L,
                -0x11fef5d90a0c527dL, 0x10EFE8F4411979A6L, 0x5DCDA10C7DE93A10L, 0x4A1BEE1D1248E92CL,
                0x53BFF2DB21847339L, -0x4b0af330595dc2f7L, 0x5FB4BC9CD84798CDL, -0x1775d274f8e3a907L,
                0x7F7771695A756A9CL, -0x3a0fd18e5f45e144L, -0x599c0654bdea198eL, 0x2EB19E22DE5FBB78L,
                0x0DB9CE0F2594BA14L, -0x7dadf19c6899b27cL, 0x2F031E6A0208EA98L, 0x5C7F2144A1BE6BF0L,
                0x7A37CB1CD16362DBL, -0x7c1f71d4b4cee39cL, -0x308fb8645469f1ceL, -0x7a945679462118e2L,
                -0x4ab87378850a9317L, -0x4701bd77a09e2903L, 0x1BDD0156966238C8L, 0x622157923EF8A92EL,
                -0x36800bdeebb8908L, -0x6282caf7a9bad315L, 0x4C90C9B0E0A71256L, 0x2308502DFBCB016CL,
                0x2D7A03FAA7A64845L, -0xb9174c740393b55L, -0x424107022b882146L, 0x3AAC4CEBC8079B79L,
                -0xf634efa177862f4L, 0x27FA6A10AC8A58CBL, -0x769f183ebfe2f316L, 0x1A6F811E4A356928L,
                -0x6f3b04f88c2e6901L, 0x43501A2F609D0A9FL, -0x85ae91f39c0c86aL, 0x1CE4A6B3B8DA9252L,
                0x1324752C38E08A9BL, -0x5a579b8cc413eab1L, 0x2BF124575549B33FL, -0x289924eabbf23a39L,
                -0x582e861c61bd486eL, -0x2520eae59e66802dL, -0x795fcba13fd8ebddL, 0x38D5517B6DA939A4L,
                0x6518F077104003B4L, 0x02791D90A5AEA2DDL, -0x772d987663b5a2f6L, -0x6cf09920f5d79a3eL,
                0x4EE9D4204509B08BL, 0x325538916685292AL, 0x412907BFC533A842L, -0x4d81d49dabb2398dL,
                0x6C5304456295E007L, 0x5AF406E95351908AL, 0x1F2F3B6BC123616FL, -0x3c84f623adaa1a3aL,
                0x3967D133B1FE6844L, 0x298839C7F0E711E2L, 0x409B87F71964F9A2L, -0x16c7523c24b4f8e7L,
                0x0C0B4E47F9C3EBF4L, 0x5534D576D36B8843L, 0x4610A05AEB8B02D8L, 0x20C3CDF58232F251L,
                0x6DE1840DBEC2B1E7L, -0x5f1721f94f05e2f8L, 0x7B854B540D34333BL, 0x42E29A67BCCA5B7FL,
                -0x2759f7753bc822f2L, -0x39c44c5626bc127fL, 0x21714DBD5E65A3B1L, 0x6761EDE7B5EEA169L,
                0x2431F7C8D573ABF6L, -0x2ae0397a1e5c98e6L, 0x5E063CD40410C92DL, 0x283AB98F2CB04002L,
                -0x70143f934d0d0870L, 0x17D64F116FA1D33CL, -0x1f8ca60e56611b56L, 0x784ED68C74CDC006L,
                0x6E2A19D5C73B42DAL, -0x78ed4be9e38fba3dL, 0x371582E4ED93216DL, -0x531c6fbeb6c60904L,
                0x7EC5F12186223B7CL, -0x3f4f6bfbd453e905L, -0x628bac865ad8141L, 0x737C3F2EA3B68168L,
                0x33E7B8D9BAD278CAL, -0x565cd5cb3dd00145L, -0x1b7e9c33012042f3L, -0x71a6bfdb915a5990L,
                0x51C6EF4B842AD1E4L, 0x22BAD065279C508CL, -0x26eb773de79f7312L, 0x319EA5491F7CDA17L,
                -0x2c6b1ed7ecb363a0L, 0x094BF43272D5E3B3L, -0x6409ed5a5b55286fL, -0x334425bc2d9002f1L,
                0x34DE1F3C946AD250L, 0x4F5B5468995EE16BL, -0x206050901570886cL, 0x2648EA5870DD092BL,
                -0x40381a928e268399L, -0x22194d00b0de2ab7L, 0x3C276B463AE86003L, -0x6e8984b0507938e1L,
                0x68A13E7835D4B9A0L, -0x4973eea0fcf3602cL, 0x141DD2C916582001L, -0x67c2708222acdb54L,
                0x64AA703FCC175254L, -0x3d36766b71fd4bdaL, 0x3E5E76D69F46C2DEL, 0x50746F03587D8004L,
                0x45DB3D829272F1E5L, 0x60584A029B560BF3L, -0x451a758c003239eL, -0x5ea5a1b19352b318L,
                0x4BA96E55CE1FB8CCL, 0x08F9747AAE82B253L, -0x3efdebb30804b8e5L, -0x60fbd7670c1471caL,
                0x068B27ADF2EFFB7AL, -0x1235680173f5a142L, 0x778E0513F4F7D8CFL, 0x302C2501C32B8BF7L,
                -0x726d2203e8a3aab3L, -0x79a3a80b9fad0a1L, -0x150ccfe45d4d0bdcL, -0x559748134429f27aL,
                -0x6670f0cafefb8ab4L, 0x0000000000000000L, -0xed1ceb2cb2f3314L, 0x710522BE061823B5L,
                -0x50d7f266cf3ffa3fL, -0x6802a31da296c39bL, 0x19A41CC633CC9A15L, -0x6a7bbe8d07386148L,
                -0x23abcd486c897b57L, -0x6bc93ec5db6f30a8L, -0x7fd4ec0ccd3710a7L, -0x3bbd51c68312b0a4L,
                -0x5e327101c54727eL, -0xd1a536ab2d6c02fL, 0x6AD823E8907A1B7DL, 0x4D2249F83CF043B6L,
                0x03CB9DD879F9F33DL, -0x21d2d0d8c927d98cL, 0x2A43A41F891EE2DFL, 0x6F98999D1B6C133AL,
                -0x2b52b932c20bc906L, -0x44ca20afd967da40L, -0x69b023557ec1927bL, -0x14be4fac811a5a3cL,
                0x0540BA758B160847L, -0x5be51bc41844bb51L, -0x1c473bd62f98e869L, -0x7e666c4411604147L,
                -0x5165722e1368abdfL, -0xca8d3226e8191cfL, 0x6393D7DAE2AFF8CEL, 0x47A2201237DC5338L,
                -0x5cdcbc2136fc11cbL, 0x79FC56C4A89A91E6L, 0x01B28048DC5751E0L, 0x1296F564E4B7DB7BL,
                0x75F7188351597A12L, -0x24926aad4231d1cdL, 0x1E9DBB231D74308FL, 0x520D7293FDD322D9L,
                -0x1df5bb9ef3cfb989L, -0x1111d2d4b152bdbL, -0x35cf0211df7ff98bL, 0x61EACA4A47015A13L,
                -0x18b501eb78d9b1d0L, 0x2CC883B27BF119A5L, 0x1664CF59B3F682DCL, -0x57ee5583e18750a5L,
                0x1D5626FB648DC3B2L, -0x48c16ee820a431ccL, -0x2fa0830f954a90a3L, -0x2da80f532ecd8e8L,
                0x574DC8E676C52A9EL, 0x0739A7E52EB8AA9AL, 0x5486553E0F3CD9A3L, 0x56FF48AEAA927B7EL,
                -0x418a9ada5271d279L, 0x7D0E6CF9FFDBC841L, 0x3B1ECCA31450CA99L, 0x6913BE30E983E840L,
                -0x52aeeff66a9158e4L, -0x4e4a4945d24bcab2L, 0x4469BDCA4E25A005L, 0x15AF5281CA0F71E1L,
                0x744598CB8D0E2BF2L, 0x593F9B312AA863B7L, -0x104c7591d65b039dL, 0x6B6AA3A04C2D4A9DL,
                0x3D95EB0EE6BF31E3L, -0x5d6e3c69eaab402bL, 0x18169C8EEF9BCBF5L, 0x115D68BC9D4E2846L,
                -0x4578a0e705308be0L, -0x2e120347491dc143L, -0x4ff8c90d0e1c9b52L, -0x7b26d6319a764902L,
                0x70B7A2F6DA4F7255L, 0x0E7253D75C6D4929L, 0x04F23A3D574159A7L, 0x0A8069EA0B2C108EL,
                0x49D073C56BB11A11L, -0x755485e6c61b0029L, -0x32f6a5f4f1c75311L, -0x36049fc9a6860ab8L,
                -0x6d4219682980cbdeL, -0x3876cc1efaeb439fL, -0x1e3e26468a364ab6L, -0x2dd99e9f30e43280L,
                -0x65bb6d128702798fL, -0x4c3354d577e5686dL, 0x72CEBF667FE1D088L, -0x292ba4a267a56bd9L
            ), longArrayOf(
                -0x37ee57fa73c0aa22L, 0x65F5B43196B50619L, -0x8b0694e298f91bdL, -0x7a62e17434bc2ccaL,
                0x5AAB8A85CCFA3D84L, -0x63840663d6a0303L, -0x5de02a5e21b49cf1L, -0x324c1089c474ba93L,
                -0x7fc0a60783083c7bL, -0x4d838c41a0ce6ec4L, -0x671c5399cc4fb7dfL, -0x409e98b3d94707e8L,
                0x0FFBC995C4C130C8L, -0x555f79dfef89e568L, 0x6057F342210116AAL, -0x9c389f3f9ab33cbL,
                0x2DDB45CC667D9042L, -0x430ba569b42bfc7eL, 0x68E8A0C3EF3C6F3DL, -0x58426d2d96008c44L,
                0x290AE20201ED2287L, -0x4821cb32177a7e71L, -0x26fe1158229efa65L, -0x2905d8cde65fcaadL,
                -0x2a90e5178b333137L, -0x15cedba3d17c0aacL, 0x7034555DA07BE499L, -0x31d92d53a9184109L,
                -0x2e9e7a85afab1c8L, 0x6A0E7DA4527436D1L, 0x5BD86A381CDE9FF2L, -0x35088a9dce88f3ceL,
                -0x4f6551261d863730L, 0x5DEF1091C60674DBL, 0x111046A2515E5045L, 0x23536CE4729802FCL,
                -0x3af343080a49c306L, 0x73A16887CD171F03L, 0x7D2941AFD9F28DBDL, 0x3F5E3EB45A4F3B9DL,
                -0x7b1101c9e4988ec0L, 0x3DB8E3D3E7076271L, 0x1A3A28F9F20FD248L, 0x7EBC7C75B49E7627L,
                0x74E5F293C7EB565CL, 0x18DCF59E4F478BA4L, 0x0C6EF44FA9ADCB52L, -0x39667ed2672538a0L,
                0x788B06DC6E469D0EL, -0x39a07158ade13b2L, 0x30A5F7219E8E0B55L, 0x2BEC3F65BCA57B6BL,
                -0x222fb696450e48a2L, -0x666fb3241c6b15a9L, 0x14B201D1E6EA40F6L, -0x444f3f7dbed7b523L,
                0x50F20463BF8F1DFFL, -0x172806c46c345348L, 0x4D8CB68E477C86E8L, -0x3e22e4c66dd971c1L,
                0x7C5AA11209D62FCBL, 0x2F3D98ABDB35C9AEL, 0x671369562BFD5FF5L, 0x15C1E16C36CEE280L,
                0x1D7EB2EDF8F39B17L, -0x256b2c824ff201ffL, -0x78843c1389f47526L, -0x347b6a201eac51bcL,
                0x05A24773B7B410B3L, 0x12857B783C32ABDFL, -0x71488f2f97edaec5L, 0x536739B9D2E3E665L,
                0x584D57E271B26468L, -0x28763870367b68dbL, -0x56ca440582e51efeL, -0x74eac85c2059be78L,
                -0x2f32a2643c872186L, 0x4AC82C9A4D80CFB7L, 0x42777F1B83BDB620L, 0x72D2883A1D33BD75L,
                0x5E7A2D4BAB6A8F41L, -0xb25549444e36a27L, -0x6fa300180272ce4aL, -0x7c559bddee64c7e1L,
                -0x3f51047bbdfdd3b7L, -0x5f06f7399cfcc51dL, -0x5bd750f7fb6c77daL, -0x521be3cbe575ac39L,
                -0x518ede11881957a3L, -0x3b80a3b5da6d6174L, -0x4ac71655aa32279dL, 0x06377AA9DAD8EB29L,
                -0x5e7517844cd8676bL, 0x6EDFDA6A35E48414L, 0x6B7D9D19825094A7L, -0x2be305aa5b179341L,
                -0x1a35123615bd3a64L, -0x5c93cae3f1903e87L, 0x5181E4DE6FABBF89L, -0xf3acfe7b2e82cL,
                -0x62be14ea7bfba76eL, 0x1C0D525028D73961L, -0xe8713e7f3577a96L, -0x65fa8efe7107ee33L,
                0x4091A27C3EF5EFCCL, 0x19AF15239F6329D2L, 0x347450EFF91EB990L, -0x1ee4b5f8722d88a7L,
                -0x46a9e21a039feccfL, -0x6ed0e0a5d2566c40L, 0x1654DCB65BA2191AL, 0x3E2DDE098A6B99EBL,
                -0x759928e1f07d1c02L, -0x73ae52482aa5f729L, 0x4533E50F8941FF7FL, 0x02E6DD67BD4859ECL,
                -0x1f975545a2092ad1L, -0x3db7d91c00b58a5bL, 0x6C39070D88ACDDF8L, 0x6486548C4691A46FL,
                -0x2e4142d9eca383f4L, -0x4cf06cfc70eaccb6L, -0x7d267b603e406597L, -0x63cdf457abdf051cL,
                -0x5ad7dbc5006f899L, -0x612b293016975cf8L, -0x47da02a7d3bb4eb9L, -0x64896e43a1234c45L,
                -0x38159e6fb7019aeaL, 0x1063A61F817AF233L, 0x47D538683409A693L, 0x63C2CE984C6DED30L,
                0x2A9FDFD86C81D91DL, 0x7B1E3B06032A6694L, 0x666089EBFBD9FD83L, 0x0A598EE67375207BL,
                0x07449A140AFC495FL, 0x2CA8A571B6593234L, 0x1F986F8A45BBC2FBL, 0x381AA4A050B372C2L,
                0x5423A3ADD81FAF3AL, 0x17273C0B8B86BB6CL, -0x17cda7237964a5eL, 0x287902BFD1C980F1L,
                -0xa56b42994c7c851L, -0x777ff5864d3545eeL, 0x55504310083B0D4CL, -0x20c96bf1f846114eL,
                0x04D1A7CE6790B2C5L, 0x612413FFF125B4DCL, 0x26F12B97C52C124FL, -0x79f7dcae59d0d754L,
                -0x106c9cd066c81a19L, 0x3507B052293A1BE6L, -0x18d3cf51a8f56390L, -0x2ca79fbe51ebda20L,
                -0x21ba8b4c2862b33cL, -0x6d45dd7fbf3a97a6L, -0xff4f35a2373d8e4L, -0x41ed780e0963a592L,
                -0xc61ce804e1f237aL, 0x495D114020EC342DL, 0x699B407E3F18CD4BL, -0x235c562b952aead8L,
                0x0D1D14F279896924L, 0x0000000000000000L, 0x593EB75FA196C61EL, 0x2E4E78160B116BD8L,
                0x6D4AE7B058887F8EL, -0x19a02fec78d1c1faL, 0x7A6DDBBBD30EC4E2L, -0x5368037635510e4fL,
                0x09CCB33C1E19DBE1L, -0x760c153b9d11e79cL, 0x7770CF49AA87ADC6L, 0x56C57ECA6557F6D6L,
                0x03953DDA6D6CFB9AL, 0x36928D884456E07CL, 0x1EEB8F37959F608DL, 0x31D6179C4EAAA923L,
                0x6FAC3AD7E5C02662L, 0x43049FA653991456L, -0x542c99623fad4712L, -0x50fd3eac583df5d5L,
                0x3CCB036E3723C007L, -0x6c363dc26f1e35d4L, -0x3cc439a1d091282dL, 0x4CFF56339758249EL,
                -0x4e16b19bcda2955aL, 0x37E16D359472420AL, 0x79F8E661BE623F78L, 0x5214D90402C74413L,
                0x482EF1FDF0C8965BL, 0x13F69BC5EC1609A9L, 0x0E88292814E592BEL, 0x4E198B542A107D72L,
                -0x333ff034145018e5L, 0x1B49C844222B703EL, 0x2564164DA840E9D5L, 0x20C6513E1FF4F966L,
                -0x453cdfc06ef31755L, -0xd122e3d9e3b8110L, -0x7eb346ba532c9e0dL, -0x6a01476bb5c6defbL,
                0x5C9CF02C1622D6ADL, -0x68e79a0c088e8717L, -0x427845d4640f5e0cL, 0x444005B259655D09L,
                -0x128a41b7db8043f5L, 0x7596122E17CFF42AL, -0x4bb4f6e87a1685ebL, -0x69947ab1d8aa2561L,
                -0x111f7c6db6ecb86fL, 0x32432A4623C652B9L, -0x57b9a4b852c1bc8cL, -0x74ba0dbed4ea175L,
                0x2417F6F078644BA3L, -0x4de9d0180225aefL, 0x4BBBCC279DA46DC1L, 0x0173E0BDD024A276L,
                0x22208C59A2BCA08AL, -0x703b6f9247c90cb3L, -0x1b46f28bc5999816L, 0x7147B5E0705F46EFL,
                0x2782CB2A1508B039L, -0x13f9a10a0ba4e183L, 0x21B5B183CFD05B10L, -0x2418cc3f9fd6a389L,
                -0x6058c98dc6b3fe82L, -0x30aacdee793ce37fL, -0x278df1e5f2ba5813L, 0x3B8F997A3DDF8958L,
                0x3AFC79C7EDFB2B2EL, -0x165be679bc10f132L, 0x5F09CDF67B4E2D37L, 0x4F6A6BE9FA34DF04L,
                -0x49522b8fc75edc07L, -0x72ddb2f5fa81555fL, -0x369db747a3e40858L, -0x1c02689fcf65d14bL,
                0x0B2A6E5BA351820DL, -0x14bd3b1e0158a8deL, -0x6b72a7d665e27c8dL, 0x7FCF9CC864BAD451L,
                -0x5aa4b04a2b48d5b0L, 0x08BF5381CE3D7997L, 0x46A6D8D5E42D04E5L, -0x2dd47f0381cf786aL,
                0x57B69E77B57354A0L, 0x3969441D8097D0B4L, 0x3330CAFBF3E2F0CFL, -0x1d7188221f41733dL,
                0x62B12E259C494F46L, -0x59318d9046242e36L, 0x41E242C1EED14DBAL, 0x76032FF47AA30FB0L
            ), longArrayOf(
                0x45B268A93ACDE4CCL, -0x5080f4177bab62f8L, 0x048354B3C1468263L, -0x6dabca3d37f1012eL,
                -0x11b1c80d80200459L, 0x167A33920C60F14DL, -0x4edc4ad15fc1a7cL, 0x4A0CAB53FDBB9007L,
                -0x621509c7f08775e7L, -0x34b713aa70f34cd6L, -0x4a623b4d29010820L, -0x232435dd0b0c134aL,
                0x11DF5813549A9C40L, -0x1cc02120a975312dL, -0x5f3e37edbcdd163dL, 0x07A56B8158FA6D0DL,
                0x77279579B1E1F3DDL, -0x264e748bbdd53ffcL, -0x4713d26000543d6cL, -0xb530757d28a6eb1L,
                0x7BBF69B1EF2B6878L, -0x3b09d050b785381fL, 0x76CE809CC67E5D0CL, 0x6711D88F92E4C14CL,
                0x627B99D9243DEDFEL, 0x234AA5C3DFB68B51L, -0x6f64e0ead9d24093L, 0x4F66EA054B62BCB5L,
                0x1AE2CF5A52AA6AE8L, -0x415fac042f31feb8L, -0x1297f73f199ceb37L, 0x43FE16CD15A82710L,
                -0x32fb6dce5f968f0aL, -0x184375936833b350L, 0x337CE835FCB3B9C0L, 0x65DEF2587CC780F3L,
                0x52214EDE4132BB50L, -0x6a0ea1bc6f0b6c21L, -0x78f7c69da22d1f0fL, 0x41313C1AFB8B66AFL,
                -0x6e8df50fae4dee44L, 0x477D427ED4EEA573L, 0x2E3B4CEEF6E3BE25L, -0x7d9d87cb14f433bdL,
                -0x63fc1c228718db38L, 0x2877328AD9867DF9L, 0x14B51945E243B0F2L, 0x574B0F88F7EB97E2L,
                -0x77490567655b6bc6L, 0x19C4F068CB168586L, 0x50EE6409AF11FAEFL, 0x7DF317D5C04EABA4L,
                0x7A567C5498B4C6A9L, -0x4944047fb0bde772L, 0x3CC22BCF3BC5CD0BL, -0x2fbcc91555c688edL,
                -0xfd053e413ccecd4L, 0x2506DBA7F0D3488DL, -0x2819a2940d3ce5e2L, 0x5EB9B2161FF820F5L,
                -0x7bd1f9af3b91f061L, 0x716BEB1D9E843001L, -0x56cc8a7354cea12cL, 0x3FE414FDA2792265L,
                0x27C9F1701EF00932L, 0x73A4C1CA70A771BEL, -0x6be7b4591894c2f2L, 0x40D829FF8C14C87EL,
                0x0FBEC3FAC77674CBL, 0x3616A9634A6A9572L, -0x70ec6ee63da106c9L, -0xaba12b2a515c062L,
                -0x17fdb669af45c785L, 0x6437E7BD0B582E22L, -0x19aa60761fac1d9fL, -0x7f52ad1cfad77204L,
                0x6DC55A23E34B9935L, -0x21eb1f0ae52f52f7L, -0x39c6fa8759a679a2L, -0x69289e8ef6b7834fL,
                -0x1d2934c5deea9ffeL, 0x01E915E5779FAED1L, -0x524fdec095882349L, -0x677f4891465e5955L,
                0x5D9F8D248644CF9BL, -0x2a1bac93a99d9a8L, -0xe39460164534203L, -0x15329cbe4166863cL,
                -0x1058dde8f7bfaa8aL, 0x510771ECD88E543EL, -0x3d45ae3498e0fbc3L, 0x0AD482AC71AF5879L,
                -0x18785fba32536caL, -0x4dc750cc71fb6513L, -0x42799336b68d11daL, 0x615DA6EBBD810290L,
                0x3295FDD08B2C1711L, -0x7cbfb9f8c40f516L, -0xcf66cd68a7003beL, 0x1CAEB13E7DCFA934L,
                -0x45dcf8b7ee777cd5L, 0x24EFCE42874CE65CL, 0x0E57D61FB0E9DA1AL, -0x4c2e45290664cbc4L,
                -0x3f8a84e376c3ba7eL, 0x2B510DB8403A9297L, 0x5C7698C1F1DB614AL, 0x3E0D0118D5E68CB4L,
                -0x29f0b7717aa34b31L, -0x5169e1f20c34cc27L, 0x3A8E55AB14A00ED7L, 0x42170328623789C1L,
                -0x7c74922e636b9d6eL, -0x76a0108212c4c515L, -0x30344719b1b5ceb7L, 0x064C7E642F65C3DCL,
                0x3D2B3E2A4C5A63DAL, 0x5BD3F340A9210C47L, -0x4b8b2ea85e9ea6cfL, -0x53a6cb25e2178d9aL,
                0x6EE365117AF7765BL, -0x37912c98e94fa3bcL, -0x645977a3dfe2b63bL, -0x46fac78577cb93bbL,
                0x131072C4BAB9DDFFL, -0x40b6b9e158ae5067L, -0x2ad68843e31fa45fL, -0x4f087a1b9fd824aeL,
                0x546D30BA6E57788CL, 0x305AD707650F56AEL, -0x3678397d9ed00d6bL, -0x5a5476bb0a043a8fL,
                0x7ED528E759F244CAL, -0x72234431d3824778L, -0x55eab541cd724e46L, 0x1E619BE993ECE88BL,
                0x09F2BD9EE813B717L, 0x7401AA4B285D1CB3L, 0x21858F143195CAEEL, 0x48C381841398D1B8L,
                -0x348af2c4d067777L, 0x39A86A998D1CE1B9L, 0x1F888E0CE473465AL, 0x7899568376978716L,
                0x02CF2AD7EE2341BFL, -0x7a38ec4a4c0e5eb2L, -0x6e901ed4ba9819L, 0x7C1A0230B7D10575L,
                0x0C98FCC85ECA9BA5L, -0x5c1808df2561f953L, 0x6A6031A2BBB1F438L, -0x68c18b6b81282da0L,
                0x2CF4663918C0FF9AL, 0x5F50A7F368678E24L, 0x34D983B4A449D4CDL, 0x68AF1B755592B587L,
                0x7F3C3D022E6DEA1BL, -0x5403a0a4baede095L, 0x0D71E92D29553574L, -0x20020aef92b0fc28L,
                0x081BA87B9F8C19C6L, -0x24815e5c53f67e45L, -0x4435ed5299e8d206L, 0x79704366010829C7L,
                0x179326777BFF5F9CL, 0x0000000000000000L, -0x14db895b36f928ebL, 0x724DD42F0738DF6FL,
                -0x48ad119ac72249a1L, 0x37FFBC863DF53BA3L, -0x71057b034a3ea81aL, -0x1614a38cd8da6956L,
                0x1B0BDABF2535C439L, -0x791ed378d5b2b1e0L, -0x66965d7431c1f786L, -0x504d1486263b4abL,
                0x056A4156B6D92CB2L, 0x5A3AE6A5DEBEA296L, 0x22A3B026A8292580L, 0x53C85B3B36AD1581L,
                -0x4ee16ffee8478a7dL, -0x3ae0c5b5c01a96d0L, -0x1fe61e1230c9de43L, -0x137ee2da6e0345e8L,
                0x445B7D4C4D524A1DL, -0x57259f9623510ffbL, 0x58F5CC72309DE329L, -0x2b3f9da694800a90L,
                -0x31dd52fcc62a6068L, 0x591CD99747024DF8L, -0x746f3a55fce784acL, -0x99c2d803ca92f10L,
                -0x27a7616eca4a912bL, 0x35309651D3D67A1CL, 0x12F96721CD26732EL, -0x2d73e3c2bbe5c954L,
                0x492A946164077F69L, 0x2D1D73DC6F5F514BL, 0x6F0A70F40D68D88AL, 0x60B4B30ECA1EAC41L,
                -0x2c9af627cc7a6783L, 0x0B3D97490630F6A8L, -0x613336f5693b9a89L, -0x5df11d3a52fe5784L,
                -0x1b654aa1f18f5c22L, -0x5bbd635e7d9b9460L, -0x25684bb92469d096L, -0x3312782b280921d9L,
                0x2AB8185D37A53C46L, -0x60da23101ea4345aL, -0x3e639106015c14adL, -0x589b5c6ce4277b32L,
                0x2FD2590B817C10F4L, 0x56A21A6D80743933L, -0x1a8c5f448610f2f1L, 0x155C0CA095DC1E23L,
                0x6C2C4FC694D437E4L, 0x10364DF623053291L, -0x22cd20387c93bd99L, 0x03263F3299BCEF6EL,
                0x66F8CD6AE57B6F9DL, -0x73ca51d4a41de9a7L, 0x31B3C2E21290F87FL, -0x6c42dfd8406eaffdL,
                0x69460E90220D1B56L, 0x299E276FAE19D328L, 0x63928C3C53A2432FL, 0x7082FEF8E91B9ED0L,
                -0x439086d3c112bf09L, 0x4C40D537D2DE53DBL, 0x75E8BFAE5FC2B262L, 0x4DA9C0D2A541FD0AL,
                0x4E8FFFE03CFD1264L, 0x2620E495696FA7E3L, -0x1e0f0bf747567094L, -0x2e55dcf02259263eL,
                -0x382fef622e39d771L, -0x75862fb08b782a7bL, 0x4694579BA3710BA2L, 0x38417F7CFA834F68L,
                0x1D47A4DB0A5007E5L, 0x206C9AF1460A643FL, -0x5ed72208cb42b8eeL, -0x7ebbb8f98d48dcd3L,
                -0xd1f7933fdefad6dL, 0x182DE58DBC892B57L, -0x355e064f076ce205L, 0x6B892447CC2E5AE9L,
                -0x622ee7afbdf5bc5L, 0x4BE5BEB68A243ED6L, 0x5584255F19C8D65DL, 0x3B67404E633FA006L,
                -0x5972498993b8d5e1L, -0x87538654b3681dfL, -0x3cacbbd1ef7f5514L, -0x65b06246a87d18ecL
            ), longArrayOf(
                0x05BA7BC82C9B3220L, 0x31A54665F8B65E4FL, -0x4e49ae088ab80b2cL, -0x7405f27a845b997eL,
                -0x7a5693a55e956745L, -0x66f05106f7148637L, -0x5ea1c85db80b59d3L, 0x76857DCD5D27741EL,
                -0x73af47ff5e7df44L, -0x419a234dfe085d4cL, 0x666D1B986F9426E7L, 0x4CC921BF53C4E648L,
                -0x6abef5f06c2635beL, 0x20CDCCAA647BA4EFL, 0x429A4060890A1871L, 0x0C4EA4F69B32B38BL,
                -0x3325c9d221cab32dL, -0x6923dc4383a4d057L, -0x3cf64497557ae54dL, -0x2d9ece58c9b71fedL,
                0x021DC52941FC4DB2L, -0x32a525488fb41b76L, -0x58869a267b128e1aL, 0x32386FD61734BBA4L,
                -0x17d2922ac7548dbbL, 0x5C2147EA6177B4B1L, 0x5DA1AB70CF091CE8L, -0x536f80318d474201L,
                0x57C85DFD972278A8L, -0x5b1bb39594906bf3L, 0x3851995B4F1FDFE4L, 0x62578CCAED71BC9EL,
                -0x2677d44f3fe2d3f6L, -0x6e8462a2eec3afc5L, -0x5d3ce1ee5789bc3aL, -0x1b9c36dc5c663e32L,
                -0x8e9793a81578924L, -0x784b568c1f692af7L, -0x50f2a98262c5a7ecL, -0x4bf3d5c0a623390cL,
                0x3602F88495D121DDL, -0x2c1e22c267c9b7b6L, -0x6ba18e55b99771bL, 0x7518547EB2A591F5L,
                -0x6c99a78baf3fe277L, -0x6157efe79a73f9a5L, 0x4F54080CBC4603A3L, 0x2D0384C65137BF3DL,
                -0x23cdaf871379e1d6L, -0x15cf570386a8c009L, 0x214D2030CA050CB6L, 0x65F0322B8016C30CL,
                0x69BE96DD1B247087L, -0x246a11667e1e9e48L, -0x2e03e7eb2635fa08L, -0x7df12d4433f218d7L,
                0x63D76050430F14C7L, 0x3BCCB0E8A09D3A0FL, -0x71bf89b2a8c0ab5eL, 0x39D175C1E16177BDL,
                0x12F5A37C734F1F4BL, -0x54c83ed0e0203d93L, 0x5648B167395CD0F1L, 0x6C04ED1537BF42A7L,
                -0x1268e9e2ebcfbf9bL, 0x7D6C67DAAB72B807L, -0x13e8057845b117c4L, -0x20508634fcfb043fL,
                0x733F060571BC463EL, 0x78D61C1287E98A27L, -0x2f830b71884b525fL, -0x463d9dac936f22daL,
                -0x1dbb64a79f7fe9fbL, -0x703f652806be0305L, -0x5273156b41b92f2L, -0x5cbc0d74f9f71461L,
                -0x64ed942fb6e8cb85L, -0x656d78b5189663deL, 0x1B017C42C4E69EE0L, 0x3A4C5C720EE39256L,
                0x4B6E9F5E3EA399DAL, 0x6BA353F45AD83D35L, -0x18011f6fb3e4dbdbL, 0x22D009832587E95DL,
                -0x7bd67f3ff0ebcf1eL, -0x394c3f5f79e1d76dL, 0x087433A419D729F2L, 0x341F3DADD42D6C6FL,
                -0x11f5c051044d5a72L, 0x4AEE73C490DD3183L, -0x5548d24a4e5e95ccL, -0x56d5fbf9a1dc7021L,
                0x7B4B35A1686B6FCCL, 0x6A23BF6EF4A6956CL, 0x191CB96B851AD352L, 0x55D598D4D6DE351AL,
                -0x369fb21a0d51810dL, 0x1CA6C2A3A981E172L, -0x21d06aae5285ac68L, 0x3025AAFF56C8F616L,
                0x15521D9D1E2860D9L, 0x506FE31CFA45073AL, 0x189C55F12B647B0BL, 0x0180EC9AAE7EA859L,
                0x7CEC8B40050C105EL, 0x2350E5198BF94104L, -0x10752ccbaa33f229L, 0x07A7BEE16D677F92L,
                -0x1a1cda46f2189669L, 0x5A061591A26E637AL, -0x49ee10e9e7df74baL, 0x09F4DF3EB7A981ABL,
                0x1EBB078AE87DACC0L, -0x486efc7349a1dce1L, 0x0FD38D4574B05660L, 0x67EDF702C1EA8EBEL,
                -0x45a0b41f7cedc733L, -0x1c3b883d310141a4L, 0x0DCE486C354C1BD2L, -0x73a24c9be93ce6f0L,
                0x26EA9ED1A7627324L, 0x039D29B3EF82E5EBL, -0x60d7037d340d51feL, -0x575517630fa2d87aL,
                0x431AACFA2774B028L, -0x30b8e061ce4856c8L, 0x581BD0B8E3922EC8L, -0x4387e664bff410faL,
                -0x6f048e3840bd079eL, 0x1F3BEB1046030499L, 0x683E7A47B55AD8DEL, -0x6770bd9c596a2e70L,
                -0x27f738d5919c7badL, 0x0627527BC319D7CBL, -0x144fbb9928d66852L, -0x1981f3f51d9a7384L,
                0x14D2F107B056C880L, 0x7122C32C30400B8CL, -0x75851ee02a253125L, -0x5f2124c71675f18cL,
                -0x52ef6cab2339ea5aL, 0x0BE91A17F655CC19L, -0x7222a00147424eb7L, -0x401acfd75076f513L,
                -0x29a4590a4b528596L, 0x7956F0882997227EL, 0x10E8665532B352F9L, 0x0E5361DFDACEFE39L,
                -0x31380cfb6036fe9fL, -0x9d4a9e9880a0d2L, -0x68a330d92dda7810L, 0x51EF0F86543BAF63L,
                0x2F1E41EF10CBF28FL, 0x52722635BBB94A88L, -0x51724518ccbb0fb3L, 0x410769D36688FD9AL,
                -0x4c546b21cb44469aL, -0x7fece86d720e5565L, -0x5a9b5f0f3aeec3acL, -0xece2b41424e5ee9L,
                0x7F71A2F3EA8EF5B5L, 0x40878549C8F655C3L, 0x7EF14E6944F05DECL, -0x2bb99c230aaec828L,
                -0xd5302f2adccbb04L, 0x0000000000000000L, 0x5FBC6E598EF5515AL, 0x16CF342EF1AA8532L,
                -0x4fc9429224c6a373L, 0x13754FE6DD31B712L, -0x44205885d2936f6cL, -0x76183753c5a7d4d0L,
                0x3C6B0E09CDFA459DL, -0x3b51fa76381d9adfL, 0x49735A777F5FD468L, -0x35029ba9e2d364e8L,
                -0x25eafdfcd060361fL, -0x7798dbc96bd97c97L, 0x3782141E3BAF8984L, -0x634a2acedb8fb417L,
                -0x2824b590e52c2dcdL, -0x590676bcd56c2641L, -0x62cac65475f11c50L, 0x53F2CAAF15C7E2D1L,
                0x6E19283C76430F15L, 0x3DEBE2936384EDC4L, 0x5E3C82C3208BF903L, 0x33B8834CB94A13FDL,
                0x6470DEB12E686B55L, 0x359FD1377A53C436L, 0x61CAA57902F35975L, 0x043A975282E59A79L,
                -0x2808fb7d97ced64L, -0x3ad116ec96633288L, 0x28B9FF0E7DAC8D1DL, 0x5455744E78A09D43L,
                -0x348277334cadccbfL, 0x44BD121B4A13CFBAL, 0x4D49CD25FDBA4E11L, 0x3E76CB208C06082FL,
                0x3FF627BA2278A076L, -0x3d76a80dfb044d16L, 0x453DFE81E46D67E3L, -0x6b3e196ac2589de5L,
                0x2C83685CFF491764L, -0xcd3ee6803b2135bL, 0x2B24D6BD922E68F6L, -0x4dd487bb653aeec1L,
                0x48F3B6EDD1217C31L, 0x2E9EAD75BEB55AD6L, 0x174FD8B45FD42D6BL, 0x4ED4E4961238ABFAL,
                -0x6d194b1101414a30L, 0x46A0D7320BEF8208L, 0x47203BA8A5912A51L, 0x24F75BF8E69E3E96L,
                -0xf4ec7dbec30f6b2L, -0x11da60436fe0889L, 0x276A724B091CDB7DL, -0x42070afe118ab8a1L,
                0x599B3C224DEC8691L, 0x6D84018F99C1EAFEL, 0x7498B8E41CDB39ACL, -0x1fa6a18ede83a449L,
                0x2AA43A273C50C0AFL, -0xaf4bc13c0abc492L, -0x7c71c1de9d8cb090L, -0x3f6b6d24baf800a8L,
                0x72BFEA9FDFC2EE67L, 0x11688ACF9CCDFAA0L, 0x1A8190D86A9836B9L, 0x7ACBD93BC615C795L,
                -0x38ccd3c5d79f7f36L, -0x79cbba16b11782b0L, -0x96995a02f29217bL, -0x16527eb0692a25e4L,
                0x70A22FB69E3EA3D5L, 0x0A69F68D582B6440L, -0x47bd71363d118a81L, 0x604A49E3AC8DF12CL,
                0x5B86F90B0C10CB23L, -0x1e264d1470fd0c12L, 0x29391394D3D22544L, -0x371f5e80a32f2956L,
                -0x4a73395a085d9153L, -0x7e6c04f7dc70fd3eL, -0x2a3970b9a4d0607fL, -0x300632d7702453bL,
                0x77059157F359DC47L, 0x1D262E3907FF492BL, -0x4a7ddcc1a653aa9L, -0x224d431dbd07498dL,
                0x2577B76248E096CFL, 0x6F99C4A6D83DA74CL, -0x3eeb81be1486a8ffL, -0xb7450896ed56cc9L
            ), longArrayOf(
                0x3EF29D249B2C0A19L, -0x161e9cdd49079dd1L, 0x5536994047757F7AL, -0x60b2a92a5b84f4cdL,
                -0x7dda98b9955ee8b4L, -0x470afa8214f7d04eL, -0x33b73ef40bb8a0adL, 0x373088D4275DEC3AL,
                -0x6970bcdae7f512f0L, 0x173D232CF7016151L, -0x51b12f606b9033edL, -0x2b4b8be3bac678dL,
                0x1B5B3F0DD9933765L, 0x2FFCB0967B644052L, -0x1fdc892df5767bf4L, -0x5c51c58fcd64e729L,
                0x419CBD2335DE8526L, -0x50140eea483ce67L, 0x0397074F85AA9B0DL, -0x3a752b04b7c94690L,
                -0x4139f41c03befb58L, 0x1EFF36DC4B708772L, 0x131FDC33ED8453B6L, 0x0844E33E341764D3L,
                0x0FF11B6EAB38CD39L, 0x64351F0A7761B85AL, 0x3B5694F509CFBA0EL, 0x30857084B87245D0L,
                0x47AFB3BD2297AE3CL, -0xd45a3d09094aab6L, 0x74BDC4761F4F70E1L, -0x302039bb8e123ba2L,
                -0x19ef87b3e23f50eaL, 0x7ACA29D63C113F28L, 0x2DED411776A859AFL, -0x53a0dee1665c2a12L,
                -0x2b7b06b657810cc5L, 0x3CE36CA596E013E4L, -0x2edf0f67c562bcd4L, 0x6BC40464DC597563L,
                0x69D5F5E5D1956C9EL, -0x6516a0fbc96744dcL, -0x36133725995b10bcL, -0x296af7375a4d153aL,
                -0x3bf3ddca3fafc480L, 0x38C193BA8C652103L, 0x1CEEC75D46BC9E8FL, -0x2ccefee6c8aea52fL,
                -0x271d1a9779135af1L, -0x4ec8ef72a886366fL, 0x709F3B6905CA4206L, 0x4FEB50831680CAEFL,
                -0x13ba950cdbe42dc8L, 0x58D673AFE181ABBEL, 0x242F54E7CAD9BF8CL, 0x0211F1810DCC19FDL,
                -0x6f43b244f0bc39f6L, -0x6ae7bb95625f89e3L, -0x5e40340ec0a8fed6L, 0x2BDE4F8961E172B5L,
                0x27B853A84F732481L, -0x4f4e19bc20e0b49fL, 0x18CC38425C39AC68L, -0x2d48082840c827dfL,
                0x3103864A3014C720L, 0x14AA246372ABFA5CL, 0x6E600DB54EBAC574L, 0x394765740403A3F3L,
                0x09C215F0BC71E623L, 0x2A58B947E987F045L, 0x7B4CDF18B477BDD8L, -0x68f64a146f939020L,
                0x73083C268060D90BL, -0x123bff1be06fc82L, 0x284948C6E44BE9B8L, 0x728ECAE808065BFBL,
                0x06330E9E17492B1AL, 0x5950856169E7294EL, -0x451b0b03193bc9b1L, -0x3584306a1cf18bb7L,
                0x7D7FD186A33E96C2L, 0x52836110D85AD690L, 0x4DFAA1021B4CD312L, -0x6ec5448a78dabb06L,
                -0x22b91346ebf0eae8L, 0x3D659A6B1E869114L, -0x3dc0d35428e6ef66L, -0x28ec01f9d22b97caL,
                -0x2f59f9a94d043e24L, 0x221C5A79DD909496L, -0x102d92435e4eb6cbL, 0x0E77EDA0235E4FC9L,
                -0x3402c6a494970947L, 0x0DE0EAEFA6F4D4C4L, 0x0422FF1F1A8532E7L, -0x69647a12129556cL,
                0x7F6E2007AEF28F3FL, 0x3AD0623B81A938FEL, 0x6624EE8B7AADA1A7L, -0x497d172237a99f85L,
                -0x58733a90d7e1d5d0L, -0x3864da85ba055f73L, 0x5B4174E0642B30B3L, 0x5F638BFF7EAE0254L,
                0x4BC9AF9C0C05F808L, -0x31a6cf750674b952L, -0x703a725633aa3c78L, -0x7fcb69389892f14fL,
                -0xcc3551e18f22846L, -0x449dfdcd915d4b41L, -0x2afdf078dfe78e35L, -0x62a358ab5648ed32L,
                -0x7be996278217c3aaL, -0x759e7b87a1498c61L, 0x420BBA6CB0741E2BL, -0xed2a49f153e31b9L,
                0x76AC35F71283691CL, 0x2C6BB7D9FECEDB5FL, -0x3324e70b3cae57dL, 0x1F79C012C3160582L,
                -0xf5452519d58b349L, -0x1e5a7fe37d10f904L, 0x67A21845F2CB2357L, 0x5114665F5DF04D9DL,
                -0x40bf02d28bd879a8L, -0x5fc6c2c048ce7c26L, 0x05A409D192E3B017L, -0x5604d730f4bf9a07L,
                0x25A9A22942BF3D7CL, -0x248a1dd8fcb9c1feL, -0x4cd91ef3a54a2f94L, -0x1869717d6a59d21aL,
                -0x468c0c4c9c9152beL, -0x20a8e2c7e63cf31bL, -0x11ab648dd628343bL, 0x12992AFD65E2D146L,
                -0x710b16fa94fd79cL, -0x48fbe1ecbfcf1d75L, -0x3fd122d5252af699L, -0x6cd4b50b7516a2f9L,
                0x6FE6FB7BC6DC4784L, 0x239AACB755F61666L, 0x401A4BEDBDB807D6L, 0x485EA8D389AF6305L,
                -0x5be43ddf524b4ec3L, 0x753B32B89729F211L, -0x6681a7b44ccddfd7L, 0x1D683193CEDA1C7FL,
                -0xa5493f36607e72L, 0x16BBD5E27F67E3A1L, -0x5a62cb11da2dcc33L, -0x6707517ac4ab5d27L,
                0x6DF70AFACB105E79L, 0x795D2E99B9BBA425L, -0x71bc8498bbccbe88L, 0x0186F6CE886682F0L,
                -0x140f6d5c44cb842eL, -0x4328059d0e72e2abL, -0x5226282fee3aa8e2L, 0x0BD3E471B1BDFFDEL,
                -0x5593d07f7115010cL, 0x5EE57D31F6C880A4L, -0xaf05b800fbb0360L, 0x1ADDC9C351F5B595L,
                -0x15899b92ccad06deL, 0x0000000000000000L, -0x7a6f60e90a71415aL, 0x46294573AAF12CCCL,
                0x0A5512BF39DB7D2EL, 0x78DBD85731DD26D5L, 0x29CFBE086C2D6B48L, 0x218B5D36583A0F9BL,
                0x152CD2ADFACD78ACL, -0x7c5c6e771d386a44L, -0x3c46259aa0806d96L, -0x61345fe4d3e2763dL,
                0x07B5F8509F2FA9EAL, 0x7EE8D6C926940DCFL, 0x36B67E1AAF3B6ECAL, -0x79f867a68fdbda55L,
                -0x487b6202ce54c97L, 0x4C7C57CC932A51E2L, -0x269bec59f175d801L, 0x263EA566C715A671L,
                0x6C71FC344376DC89L, 0x4A4F595284637AF8L, -0x250ceb1674df430eL, 0x572768C14AB96687L,
                0x1088DB7C682EC8BBL, -0x778f8a06ac85959eL, 0x2E7A4658F302C2A2L, 0x619116DBE582084DL,
                -0x578221fe7cd918f7L, -0x233fe58863966818L, -0x123c63c25382af38L, -0x59f5cc5e5f875740L,
                -0x3e57d41bad4c7469L, 0x3F746BEA134A88E9L, -0x5dd73341450265d9L, -0x541526b1f97383fcL,
                -0xb76ad4e87dd81b0L, 0x5CF48CB0FB049959L, 0x6017E0156DE48ABDL, 0x4438B4F2A73D3531L,
                -0x73ad7519b600a77bL, -0x4aea106db203048aL, 0x0C661C212E925634L, -0x4b6ce6a33a65867aL,
                -0x6325ae65de2e6fc2L, 0x32948105B5BE5C2DL, 0x194ACE8CD45F2E98L, 0x438D4CA238129CDBL,
                -0x649056354101c62cL, -0x7e4d9ff610f473bfL, -0x212e14096e5a71ebL, 0x4E6DA64D9EE6481FL,
                0x54B06F8ECF13FD8AL, 0x49D85E1D01C9E1F5L, -0x5037d9aee3f6b11dL, -0x9675ccf8a119853L,
                0x5AC7822EEC4DB243L, -0x722b83d73e66258bL, -0x76097cc824e3176eL, -0x3231c83a83de225dL,
                0x530597DE503C5460L, 0x6A42F2AA543FF793L, 0x5D727A7E73621BA9L, -0x1dcd78acf8ba620fL,
                0x56A19E0FC2DFE477L, -0x39e22c4b3263dd83L, -0x1a7880fc6795cbe5L, -0x6b614d5bea390b13L,
                0x6206119460289340L, 0x6380E75AE84E11B0L, -0x74188d49292f0e91L, 0x50929091D596CF6DL,
                -0x17986a13c1611f21L, 0x7CF927482B581432L, -0x3795c1eb113d924cL, 0x7119CDA78DACC0F6L,
                -0x1bfe7632eff34915L, -0x6d5243c5fd702009L, -0x4d5fe83d2d2cad64L, 0x200DABF8D05C8D6BL,
                0x34A78F9BA2F77737L, -0x1c4b8e6270dce0ffL, 0x45BE423C2F5BB7C1L, -0x8e1aa0102771aa3L,
                0x6853032B59F3EE6EL, 0x65B3E9C4FF073AAAL, 0x772AC3399AE5EBECL, -0x787e916807bd58a5L,
                0x110E2DB2E0484A4BL, 0x331277CB3DD8DEDDL, -0x42aef3538614605bL, 0x352179552A91F5C7L
            ), longArrayOf(
                -0x754f5697b91f9593L, 0x43C7E80B4BF0B33AL, 0x08C9B3546B161EE5L, 0x39F1C235EBA990BEL,
                -0x3e410dc899f9384eL, 0x2C209233614569AAL, -0x14feadc4903cd766L, -0x6b96ac546ca53123L,
                0x272838F63E13340EL, -0x74fbaa135ed45faeL, 0x77A1B2C4978FF8A2L, -0x5aaedd35ec1abf7aL,
                0x2276135862D3F1CDL, -0x24722021f7489302L, 0x5D1E12C89E4A178AL, 0x0E56816B03969867L,
                -0x11a0866accfc12a7L, -0x50128b74548728e3L, 0x6D929F2DF93E53EEL, -0xa275707458673d6L,
                -0x9e64e9671c63095L, -0x6a2250d08b6efb1eL, -0x13d5637f1f779bd9L, -0x31a370277da46a16L,
                -0x3b1f2666c539fd8fL, 0x4699C3A5173076F9L, 0x3D1B151F50A29F42L, -0x612afa15d438a6baL,
                0x34665ACFDC7F4B98L, 0x61B1FB53292342F7L, -0x38de3ff7f179bed0L, -0x796c32e96902848cL,
                -0x78d8ce6d8ec94eb5L, -0x2cbb93759c5e8de5L, 0x669A35E8A6680E4AL, -0x3549a70dc6af65eaL,
                -0x5b1a21b10bd17547L, 0x37A7435EE83F08D9L, 0x134E6239E26C7F96L, -0x7d86e5c3d2098b78L,
                0x3F6EF00A8329163CL, -0x71a581bd02149a6fL, 0x5CAAEE4C7981DDB5L, 0x19F234785AF1E80DL,
                0x255DDDE3ED98BD70L, 0x50898A32A99CCCACL, 0x28CA4519DA4E6656L, -0x51a677f0b34ce2deL,
                0x0D9798FA37D6DB26L, 0x32F968F0B4FFCD1AL, -0x5ff0f69bb0da7abbL, -0x5c52ae8a1db218eL,
                -0xb93ab83a24db9ebL, 0x713E80FBFF0F7E20L, 0x7843CF2B73D2AAFAL, -0x42e815c951209d4cL,
                -0x2eee4532e906d31L, 0x4ABAA7DBC72D67E0L, -0x4cbe94a252b6052dL, -0x435ce94db6eb5775L,
                0x15D150068AECF914L, -0x1d83e2141ce103c0L, 0x4FE48C759BEDA223L, 0x7EDCFD141B522C78L,
                0x4E5070F17C26681CL, -0x1969353ea7ea0c44L, 0x35D2A64B3BB481A7L, -0x7ff300d60182020aL,
                0x1ED9FAC3D5BAA4B0L, 0x6C2663A91EF599D1L, 0x03C1199134404341L, -0x852b212960dfaacL,
                -0x326269b649e42955L, -0x373c42181524ec98L, -0x2ece76604fd5049bL, 0x1D18E352E1FAE7F1L,
                -0x25c6dca51083593fL, -0x5e440a1f5711b086L, -0x6ec887fa3065f4e2L, 0x3138716180BF8E5BL,
                -0x2607c53424c31a80L, 0x0275E515D38B897EL, 0x472D3F21F0FBBCC6L, 0x2D946EB7868EA395L,
                -0x45c3db72de6bd1f7L, -0x18ddc9ba4021c67dL, -0x9b0146fd1be44fL, -0x3688be9cf2ef26a9L,
                -0x3c34e8dd4a72b134L, -0x5d85138e6351f3c5L, -0x660134ae5b73ea05L, 0x1465AC826D27332BL,
                -0x1e42fb8528a140ffL, 0x79F733AF941960C5L, 0x672EC96C41A3C475L, -0x3d801459adb97b0dL,
                0x64EFD0FD75E38734L, -0x12619ffbf8bc51e8L, -0x471d66c4610ebb3L, 0x38453EB10C625A81L,
                0x6978480742355C12L, 0x48CF42CE14A6EE9EL, 0x1CAC1FD606312DCEL, 0x7B82D6BA4792E9BBL,
                -0x62ebe384e078e5f9L, 0x5616B80DC11C4A2EL, -0x47b63e670de05889L, 0x7CA91801C8D9A506L,
                -0x4ecb71b7813d8c53L, 0x41B20D1E987B3A44L, 0x7460AB55A3CFBBE3L, -0x7b19d7fcba890df6L,
                0x1B87D16D897A6173L, 0x0FE27DEFE45D5258L, -0x7c32194735c24149L, 0x0C23647ED01D1119L,
                0x7A362A3EA0592384L, -0x49e0bf0c0e76c0f0L, 0x75D457D1440471DCL, 0x4558DA34237035B8L,
                -0x2359ee9a7803dfbdL, -0x7264982c3654d930L, 0x2B0B5C88EE0E2517L, 0x6FE77A382AB5DA90L,
                0x269CC472D9D8FE31L, 0x63C41E46FAA8CB89L, -0x48544388e9bd0ad1L, 0x7D1DE4852F126F39L,
                -0x573945cfdbcc6460L, 0x600507D7CEE888C8L, -0x70117d39e5df5052L, 0x57A2448926D78011L,
                -0x35a18d7c95ba710L, 0x072BCEBB8F4B4CBDL, 0x497BBE4AF36D24A1L, 0x3CAFE99BB769557DL,
                0x12FA9EBD05A7B5A9L, -0x173fb455a47c9425L, 0x4273148FAC3B7905L, -0x6f7c7b7ed7ae3edfL,
                -0x1aa82caf93aa4f03L, 0x72FF996ACB4F3D61L, 0x3EDA0C8E64E2DC03L, -0xf797ca91946b617L,
                0x04EAD72ABB0B0FFCL, 0x17A4B5135967706AL, -0x1c371e90fb2ac981L, -0x7b0cffd7250a8f4L,
                0x1846C8FCBD3A2232L, 0x5B8120F7F6CA9108L, -0x2b905dce1315c15aL, 0x334D947453340725L,
                0x58403966C28AD249L, -0x41290c586560de0bL, 0x68CCB483A5FE962DL, -0x2f7a8ae4a81ecea6L,
                -0x12ffdc21ad02e72L, 0x4B0E5B5F20E6ADDFL, 0x1A332DE96EB1AB4CL, -0x5c31ef0a849a39fcL,
                0x108F7BA8D62C3CD7L, -0x54f85c5eef8c271fL, 0x6B0DAD1291BED56CL, -0xd0c99bccacd3f69L,
                0x2E557726B2CEE0D4L, 0x0000000000000000L, -0x34fd5b892164afd7L, -0x1b1cd02b7461853eL,
                0x734B65EE2C84F75EL, 0x6E5386BCCD7E10AFL, 0x01B4FC84E7CBCA3FL, -0x30178ca39a6fa02bL,
                0x3613BFDA0FF4C2E6L, 0x113B872C31E7F6E8L, 0x2FE18BA255052AEBL, -0x168b48d143b75e1cL,
                0x0ABC5641B89D979BL, -0x4b955a19ddfd4992L, 0x44EC26B0C4BBFF87L, -0x596fc4a4d85afc39L,
                0x7F680190FC99E647L, -0x6857b5c558e57264L, -0x22ed121e9fc81584L, -0x3aabdae222f237b2L,
                -0x773ab3826a941cedL, 0x4D91696048662B5DL, -0x4f7f8d3366f6466eL, -0x4a21a69d3a3683afL,
                -0x7e47fc52e649c837L, -0x4d0a6826b57dcf14L, 0x0B08AAC55F565DA4L, -0xecd802dfe8d7c2aL,
                -0x52676e61870ca19dL, 0x6AB9519676751F53L, 0x24E921670A53774FL, -0x4602c2e3ea2b92b8L,
                -0x6d099e6b0425b7a1L, 0x5A35DC7311015B37L, -0x212c0b8fab8856c3L, -0x3ff5f14c7e32f273L,
                -0x447727f639a01bcaL, 0x16104997BEACBA55L, 0x21B70AC95693B28CL, 0x59F4C5E225411876L,
                -0x2a24a14af4de0b67L, 0x55D7A19CF55C096FL, -0x568db94b3c07ae61L, -0x7aad2b785d42c7cbL,
                0x54635D181297C350L, 0x23C2EFDC85183BF2L, -0x609e069133f36c87L, 0x534893A39DDC8FEDL,
                0x5EDF0B59AA0A54CBL, -0x53d392e560c76ba4L, -0x2851445f27558219L, 0x2ABFA00C09C5EF28L,
                -0x27b339b0c308d041L, 0x2003F64DB15878B3L, -0x58db38203f913608L, 0x069F323F68808682L,
                -0x33d69532ae2fe36cL, 0x055E2BAE5CC0C5C3L, 0x6270E2C21D6301B6L, 0x3B842720382219C0L,
                -0x2d0f6ff17b9547dcL, 0x52FC6F277A1745D2L, -0x396ac37316b274f1L, -0x1ff60701cf6a8ac2L,
                0x655B2C7992284D0BL, -0x67b5c82abcb8203cL, -0x154a514077f71d5bL, -0x65c02d3f6f33a946L,
                -0x635f1f0007b32fc8L, 0x4C2595E4AFADE162L, -0x2098f70b4c439cfeL, -0x409df0dc82ab1436L,
                -0x6cbd62efe3ee7da0L, 0x097D4FD08CDDD4DAL, -0x73d064a8d19f1311L, 0x708A7C7F18C4B41FL,
                0x3A30DBA4DFE9D3FFL, 0x4006F19A7FB0F07BL, 0x5F6BF7DD4DC19EF4L, 0x1F6D064732716E8FL,
                -0x6043379959b62cdL, 0x308C8DE567744464L, -0x768e4f068d5fd6d4L, -0x29e5b8dbc09e4828L,
                -0x10147aee2b37d89aL, -0x69e34941bf2eb85dL, -0x554ca0da0847ed22L, 0x76154E407044329DL,
                0x513D76B64E570693L, -0xcb865382d06f558L, -0x6474d1bb88f8637bL, 0x297EB99D3D85AC69L
            ), longArrayOf(
                0x7E37E62DFC7D40C3L, 0x776F25A4EE939E5BL, -0x1fba37af22704a53L, -0x7912a458ee00e6aeL,
                -0x16e2f426309e94cbL, 0x37E0AB256E408FFBL, -0x69f8093fcefda586L, 0x0B02F5E116D23C9DL,
                -0xc27b79404af9af4L, 0x621CFF27C40875F5L, 0x7D40CB71FA5FD34AL, 0x6DAA6616DAA29062L,
                -0x60a0cab6dc137b1eL, -0x137b83c23af83c4dL, 0x025A3668043CE205L, -0x57406193b253f4e7L,
                -0x57f741d1641446cL, -0x4a4663ad8838b05dL, 0x78D9BC95F0397BCCL, -0x1ccd1af32452d9dcL,
                -0x38b031ed6ccd8682L, 0x1729ECEB2EA709ABL, -0x3d29460966ab2e08L, 0x5D898CBFBAB8551AL,
                -0x7a658904e8227525L, 0x1BE85886362F7FB5L, -0x9bec0700ec93276L, -0x2ceef05a44481ca4L,
                0x0A2FEED514CC4D11L, -0x17cfef123280e547L, -0x5e18a21aa0bd2a7fL, -0x1121b5aa3ec4de4aL,
                -0xd0aaca006b1eb80L, 0x0CC1B46D1888761EL, -0x431ea0249ad66ec5L, 0x2D25E8975A7181C2L,
                0x71817F1CE2D7A554L, 0x2E52C5CB5C53124BL, -0x60859411063d7e3L, -0x618dd182de0d0a92L,
                -0x31e8f2647e23581aL, 0x0E9B82051CB4941BL, 0x1E712F623C49D733L, 0x21E45CFA42F9F7DCL,
                -0x347185807445f0a0L, -0x71677ce5fef049baL, 0x474CCF0D8E895B23L, -0x566d7aa7b04d856bL,
                -0x733d4a8dfaccabbdL, 0x42D5B8E984EFF3A5L, 0x012D1B34021E718CL, 0x57A6626AAE74180BL,
                -0xe603f91c27eceeL, 0x35BA9D4D6A7C6DFEL, -0x362bb3e87079129bL, 0x506523E6A02E5288L,
                0x03772D5C06229389L, -0x74fe0b01f496e140L, -0x7254275127da66fL, 0x4C4E3AEC985B67BEL,
                -0x4ef20f7d80406957L, 0x6A69279AD4F8DAE1L, -0x187976232c2a00d2L, -0x7ed1e5d4e05aac2fL,
                -0x4526f29145f35e8L, 0x1AC543B234310E39L, 0x1604F7DF2CB97827L, -0x59dbe396aee760feL,
                0x753513CCEAAF7C5EL, 0x64F2A59FC84C4EFAL, 0x247D2B1E489F5F5AL, -0x249b28e754b8b3b8L,
                0x79F4A7A1F2270A40L, 0x1573DA832A9BEBAEL, 0x3497867968621C72L, 0x514838D2A2302304L,
                -0xf509ac8028d097bL, 0x1D06023E3A6B44BAL, 0x678588C3CE6EDD73L, 0x66A893F7CC70ACFFL,
                -0x2b2db1d64a125621L, 0x3856321470EA6A6CL, 0x07C3418C0E5A4A83L, 0x2BCBB22F5635BACDL,
                0x04B46CD00878D90AL, 0x06EE5AB80C443B0FL, 0x3B211F4876C8F9E5L, 0x0958C38912EEDE98L,
                -0x2eb4c6324074fea7L, 0x397B292072F41BE0L, -0x783fbf6cec1e9722L, -0x52d91677b8355c61L,
                0x4E140C849C6785BBL, -0x2a00aae2480c27adL, -0x5f35b92ea2a35bf3L, -0x329fdf387801cb91L,
                -0x7b489230ea3c04a9L, -0x21025f035ede1b32L, 0x4B8D7B6096012D3DL, -0x6539bd52d675d39cL,
                0x0875D8BD10F0AF14L, -0x4ca83915847c8b54L, 0x4D6321D89A451632L, -0x125698f638e64dc1L,
                -0x893db440cd743faL, -0x399d2ad96ed3f70eL, 0x3CE25EC47892B366L, -0x4687d7c090b0c643L,
                -0x3f7370616297cc03L, 0x4F3917B09E79F437L, 0x593DE06FB2C08C10L, -0x297787be4e2eb426L,
                0x19B26EEE32139DB0L, -0x4b6b78998a26c1d1L, -0x7da6c888e6783fa8L, -0x6f165387c2b99e8bL,
                -0xe7d81fc009378f7L, -0x6ba23f57cac14781L, 0x4516F9658AB5B926L, 0x3F9573987EB020EFL,
                -0x47aaccf492aeb7cfL, 0x2AE6A91B542BCB41L, 0x6331E413C6160479L, 0x408F8E8180D311A0L,
                -0x100cae9e3cdaafc6L, -0x2f99dd06426a8f2bL, -0x7789265df2b472b7L, -0x5aaccecaa8c5f375L,
                -0x1e972c9b206e3bdfL, -0xbe4f6180af5d071L, 0x12B09B0F24C1A12DL, -0x25b633d356a6c23cL,
                0x1F5C34563E57A6BFL, 0x54D14F36A8568B82L, -0x5083201fbc09be66L, -0x1595d97a36bc0744L,
                -0x1a23404b2816e2d5L, -0x4d8522218662fae0L, 0x6B443CAED6E6AB6DL, 0x7BAE91C9F61BE845L,
                0x3EB868AC7CAE5163L, 0x11C7B65322E332A4L, -0x2dc3eb6e46566d30L, -0x704a67d1fcee3836L,
                0x70AC6428E0C9D4D8L, -0x76a43d69f0aa033bL, 0x76423E90EC8DEFD7L, 0x6FF0507EDE9E7267L,
                0x3DCF45F07A8CC2EAL, 0x4AA06054941F5CB1L, 0x5810FB5BB0DEFD9CL, 0x5EFEA1E3BC9AC693L,
                0x6EDD4B4ADC8003EBL, 0x741808F8E8B10DD2L, 0x145EC1B728859A22L, 0x28BC9F7350172944L,
                0x270A06424EBDCCD3L, -0x68d5120bcce3d40aL, 0x059977E40A66A886L, 0x2550302A4A812ED6L,
                -0x2275725f58fc88b9L, -0x3aea078568f16485L, 0x3023EAA9601AC578L, -0x481c55c58c04525aL,
                0x0FB699311EAAE597L, 0x0000000000000000L, 0x310EF19D6204B4F4L, 0x229371A644DB6455L,
                0x0DECAF591A960792L, 0x5CA4978BB8A62496L, 0x1C2B190A38753536L, 0x41A295B582CD602CL,
                0x3279DCC16426277DL, -0x3e5e6b556089bd8fL, 0x139D803B26DFD0A1L, -0x51ae3b2bbe17cfeaL,
                -0x27ec05bb529a203fL, -0x53f40d43ba2b2dedL, 0x23BE6A9246C515D9L, 0x49D74D08923DCF38L,
                -0x62fafcded82f9919L, 0x2F7FDEFF5E4D63C7L, -0x5b81d5feaadb82f9L, -0x664e900ed0574013L,
                0x4661D4398C972AAFL, -0x202f44375cc06abeL, -0x2358696b5ae2f935L, -0x4fdf1449825e18dbL,
                -0x45f0fa9c969255ccL, -0x1b0e5b7f2a089359L, -0x3bc71cb16aef1509L, -0x6c617edbc49b0d04L,
                -0x721051b9f8d2da31L, 0x2C08F3A3586FF04EL, -0x285a9c8a4c30c5aaL, 0x20C947CE40E78650L,
                0x43F8A3DD86F18229L, 0x568B795EAC6A6987L, -0x7ffcfee0e244dda3L, -0xac9ed2c08eba1fdL,
                0x189F75DA300DEC3CL, -0x6a8f2463c8df360dL, -0x44dde1a8948c2448L, 0x72F65240E4F536DDL,
                0x443BE25188ABC8AAL, -0x1de001c7264ca858L, -0x2bc3591181b0ee9L, -0x355c9eb4765b8114L,
                -0x1cb18cd1e399d62L, -0x7c8bd3bce4664e2cL, -0x30c5e9507c3d2996L, -0x551a57fbb66f16e4L,
                0x26271D764CA3BD5FL, -0x6e3b48b3c0a7ef07L, 0x7C6DD045F841A2C6L, 0x7F1AFD19FE63314FL,
                -0x3706a8dc72676317L, -0x58f6f8a2acf91172L, 0x55FC5402AA48FA0EL, 0x48FA563C9023BEB4L,
                0x65DFBEABCA523F76L, 0x6C877D22D8BCE1EEL, -0x33b2c40c7a1fba1dL, -0x4144964c9eea8cc2L,
                0x10EAAD6720FD4328L, -0x49314ef18e1a23d6L, -0x4233bb1098c81f49L, 0x523F158EA412B08DL,
                -0x67638b3ad249319fL, -0x6414a666d46ba218L, -0x75d31035f68890b4L, -0x5c429472a481c87cL,
                -0x14b8c24e34a276d0L, -0x3c045d3d64b55f8cL, -0x63d7e7eada31e895L, 0x683311F2D0C438E4L,
                0x5FD3BAD7BE84B71FL, -0x3912ea51a057f65L, 0x36CDB0116C5EFE77L, 0x29918447520958C8L,
                -0x5d6f8f46a69fb9f8L, 0x53120EBAA60CC101L, 0x3A0C047C74D68869L, 0x691E0AC6D2DA4968L,
                0x73DB4974E6EB4751L, 0x7A838AFDF40599C9L, 0x5A4ACD33B4E21F99L, 0x6046C94FC03497F0L,
                -0x19546d172e34715eL, 0x3354C7F5663856F1L, -0x26c11e8f508451b3L, 0x616BD27BC22AE67CL,
                -0x6d4c65efc6857c90L, -0x54374ccfb4716770L, -0x40698d789cf4fd4eL, 0x5B67D607B6FC6E15L
            ), longArrayOf(
                -0x2fce3c6831aac01aL, 0x16BA5B01B006B525L, -0x57645219d6918f38L, 0x6A1F525D77D3435BL,
                0x6E103570573DFA0BL, 0x660EFB2A17FC95ABL, 0x76327A9E97634BF6L, 0x4BAD9D6462458BF5L,
                -0xe7cf351243c08b8L, -0x3a370abd996ece01L, -0x6afbb5e323b74f35L, -0x76d69d20c307479aL,
                -0x4f461df716cf3ecbL, -0x5eb04c0f9ee58984L, -0x72d9fa0de3e9fecaL, -0x2948e6dd0133ab62L,
                0x37089438A5907D8BL, 0x0B5DA38E5803D49CL, 0x5A5BCC9CEA6F3CBCL, -0x1251db92c48c001bL,
                -0x2d4781f021dd1232L, 0x5E54ABB1CA8185ECL, 0x1DE7F88FE80561B9L, -0x52a1e578feca5f74L,
                0x2F2ADBD665CECC76L, 0x5780B5A782F58358L, 0x3EDC8A2EEDE47B3FL, -0x3626a3caf94118f1L,
                -0x7c41eee293b1fa12L, -0x59fc46f6a6c98bf0L, 0x103C81B4809FDE5DL, 0x2C69B6027D0C774AL,
                0x399080D7D5C87953L, 0x09D41E16487406B4L, -0x3229c4e7d9afa1a1L, -0x6623d0b64fd6718L,
                -0x632fabf56bc34981L, -0x4357b48076e0e83bL, 0x723D1DB3B78DF2A6L, 0x78AA6E71E73B4F2EL,
                0x1433E699A071670DL, -0x7b0de41bab9df87eL, -0x6720ccd84b2df0d1L, -0xfb6231d2c8961a4L,
                -0x24939fe669a91486L, 0x648746B2078B4783L, 0x32CD23598DCBADCFL, 0x1EA4955BF0C7DA85L,
                -0x165ebcbfe462b94bL, -0x26d5a264413de48L, -0x37ec7386f1f471e5L, 0x2EE00B9A6D7BA562L,
                -0x7a8ed476c480e04L, -0x14d70127f4156b63L, 0x564A65EB8A40EA4CL, 0x6C9988E8474A2823L,
                0x4535898B121D8F2DL, -0x54273fcdce53340cL, -0x45d16e3546798343L, 0x7960BE3DEF8E263AL,
                0x0C11A977602FD6F0L, -0x34af1e52e936cad9L, -0x151dd16bfca00277L, 0x2866D12F5DE2CE1AL,
                -0xe4e7be54640c70L, -0x606cc6217301f2bdL, -0x69b8d8373b75f409L, 0x524502C6AAAE531CL,
                -0x6463a10c53ef4bedL, 0x4FA2FA4942AB32A5L, 0x3F165A62E551122BL, -0x38beb72589191c29L,
                -0x6db7bf1a1b9b4d59L, -0x2c8d51bc29687b26L, 0x233B72A105E11A86L, -0x5b75fb6eb6be59c8L,
                -0x4b497ada3621879bL, -0x2215455359307ffeL, 0x0A9773C250B6BD88L, -0x3d7b0044a142cc6dL,
                -0x745f20b8d37095b2L, 0x2AEF6CB74D951C32L, 0x427983722A318D41L, 0x73F7CDFFBF389BB2L,
                0x074C0AF9382C026CL, -0x7595f0f4dbc5fca6L, 0x6FDAE53C5F88931FL, -0x3974676981ac753dL,
                0x44FF59C71AA8E639L, -0x1d031f31bc616dd7L, -0x5df321db862732c0L, 0x19E89FA2C8EBD8E9L,
                -0xbb944300c67d8f4L, 0x43B3533E2284E455L, -0x27d0f232716bafbaL, 0x51066F12B26CE820L,
                -0x18c6a850943abd93L, 0x081ECE5A40C16FA0L, 0x3B193D4FC5BFAB7BL, 0x7FE66488DF174D42L,
                0x0E9814EF705804D8L, -0x7ec8537a83c6283aL, -0x4e8ccdbb1e7a57dfL, 0x695C3F896F11F867L,
                -0x930f9a81c100adcL, 0x1AABF276D02963D5L, 0x2DA3664E75B91E5EL, 0x0289BD981077D228L,
                -0x6f3e02820bec9f71L, 0x3C5537B6FD93A917L, -0x55edef81c6e65d20L, 0x0686DAB530996B78L,
                -0x25594faa611c7d92L, -0x3cb1d008a9f7a579L, 0x6D5358A44FFF4137L, -0x3a78a6a4ca6b754L,
                0x7CA5095CC7D5F67EL, -0x4eb8093748ab540L, -0x4014d9546e225307L, 0x6896EFC567A49173L,
                -0x3565ce1ee183a3cdL, -0x441bbe794eccea57L, 0x0DDB793B689ABFE4L, 0x70B4A02BA7FA208EL,
                -0x1b85c5848cf806afL, -0x73132a41eb5c97deL, -0x1112b646dc4ebb27L, 0x17708B4DB8B3DC31L,
                0x6088219F2765FED3L, -0x4c0570230e0d85f7L, -0x6ef4d2ce0359f665L, 0x0F52C4A378ED6DCCL,
                0x50CCBF5EBAD98134L, 0x6BD582117F662A4FL, -0x6b3165af2b022621L, 0x2B25BCFB45207526L,
                0x67C42B661F49FCBFL, 0x492420FC723259DDL, 0x03436DD418C2BB3CL, 0x1F6E4517F872B391L,
                -0x5f7a9c439650e098L, -0x2bc15b451144794aL, 0x01CAD04C08B56914L, -0x536b3534f67f3668L,
                0x54C3D8739A373864L, 0x26FEC5C02DBACAC2L, -0x2156288741f2c4c2L, 0x040F672D20EEB950L,
                -0x1a4f15c8844d6fbbL, -0xcf54ec9344bdaa0L, 0x62019C0737122CFBL, -0x17946cf3ecd7d05fL,
                -0x33e314abd11ac8b5L, 0x538FD28AA21B3A08L, 0x1B61223AD89C0AC1L, 0x36C24474AD25149FL,
                0x7A23D3E9F74C9D06L, -0x41de091866973a13L, -0x30a0797fc9d87389L, -0x8fa29e414a563d0L,
                0x4D2B47D152DCE08DL, 0x5F9E7BFDC234ECF8L, 0x247778583DCD18EAL, -0x79845983bbea2a56L,
                0x4CE1979D5A698999L, 0x0000000000000000L, -0x139b0bdecc39690fL, -0x4a83aa963e94ee8fL,
                -0x3e386d90b9807751L, 0x654D96FE0F3E2E97L, 0x15F936D5A8C40E19L, -0x4758d3ad560e516bL,
                -0x56ae8255de24e624L, 0x58D27104FA18EE94L, 0x5918A148F2AD8780L, 0x5CDD1629DAF657C4L,
                -0x7d8b3eae9b049306L, -0x2e04ec24391fa90eL, 0x7D6FD910CF609F6AL, -0x49c0c742265655b3L,
                0x3D9FE7FAF526C003L, 0x74BBC706871499DEL, -0x209cf8cb4947add6L, 0x3AD3ED03CD0AC26FL,
                -0x52150df7c3fdc2cL, -0x3ff2bddcb1351e45L, -0x7ac73457a328916aL, -0x3bfddaf191dba715L,
                0x47BC3413026A5D05L, -0x502858e0eebd8d5cL, -0x6872087b33c09d1dL, -0x469203e15ebb387fL,
                0x21B2CF391596C8AEL, 0x318E4E8D950916F3L, -0x316aa933c16d1a9dL, 0x385A509BDD7D1047L,
                0x358129A0B5E7AFA3L, -0x190c781c9c8fd487L, -0x1f8aa2a9ac16bfffL, 0x7BE903A5FFF9F412L,
                0x12B53C2C90E80C75L, 0x3307F315857EC4DBL, -0x70504795f39e2ce2L, -0x261a227e79dec6aeL,
                0x77F8AAD29FD622E2L, 0x25BDA814357871FEL, 0x7571174A8FA1F0CAL, 0x137FEC60985D6561L,
                0x30449EC19DBC7FE7L, -0x5abf2b22be0b30d4L, -0x23df951f518516eaL, 0x5B911CD0E2DA55A8L,
                -0x4dcfa06f06b8ece3L, 0x344BF9ECBD52C6B7L, 0x5D17C665D2433ED0L, 0x18224FEEC05EB1FDL,
                -0x61a6166d7bb49ba9L, -0x65a971405b5a22f9L, -0x5c39f1978e925bacL, 0x7E2CB4C4D7A22456L,
                -0x784e89cfb35f4342L, 0x413AEEA632F3367DL, -0x66ea1c94439899c5L, 0x40F03EEA3A465F69L,
                0x1C2D28C3E0B008ADL, 0x4E682A054A1E5BB1L, 0x05C5B761285BD044L, -0x1e4072e5a4a3d6ebL,
                -0xd3f9e853cfeb38cL, -0x480a170e2ee33ca7L, 0x63CB4C4B3FA745EFL, -0x62e57bb963762095L,
                -0x1cc9cf7db4d404c3L, -0x2a0b8b0919f1105eL, -0xa73947c04d2b1e8L, 0x4676E45F0ADF3411L,
                0x20781F751D23A1BAL, -0x429d64cc7e55812fL, -0x51e288ace608e450L, -0x12e37f25cd1657cL,
                0x5509083F92825170L, 0x29AC01635557A70EL, -0x583696baae7ce2fcL, -0x719a97d9fb2b45f6L,
                0x11F651F8882AB749L, -0x288236910986c276L, -0x10d8660ad4fbd233L, 0x48EEF0B07A8730C9L,
                0x22F1A2ED0D547392L, 0x6142F1D32FD097C7L, 0x4A674D286AF0E2E1L, -0x7f0283368b73412eL,
                0x717E7067AF4F499AL, -0x6c7d6f56132e244dL, -0x771c4d6ccbb22e8eL, 0x2734158C250FA3D6L
            )
        )
    }

    abstract fun createInstance(): D

    override fun copy(): D {
        val instance = createInstance()

        iv.copyInto(instance.iv, 0, 0, 64)
        n.copyInto(instance.n, 0, 0, 64)
        sigma.copyInto(instance.sigma, 0, 0, 64)
        ki.copyInto(instance.ki, 0, 0, 64)
        m.copyInto(instance.m, 0, 0, 64)
        h.copyInto(instance.h, 0, 0, 64)

        block.copyInto(instance.block, 0, 0, 64)

        instance.bOff = bOff

        return instance
    }

    init {
        iv.copyInto(this.iv, 0, 0, 64)
        iv.copyInto(h, 0, 0, 64)
    }
}
