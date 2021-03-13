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

package com.appmattus.crypto.internal.core.bouncycastle.haraka

import com.appmattus.crypto.Algorithm

/**
 * Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
 *
 * Haraka512-256 with reference to Python Reference Impl from: https://github.com/kste/haraka
 */
@Suppress("ClassName", "MagicNumber", "LargeClass")
internal class Haraka512_256 : HarakaCore<Haraka512_256> {
    private val buffer: ByteArray
    private var off = 0

    constructor() {
        buffer = ByteArray(64)
    }

    constructor(digest: Haraka512_256) {
        buffer = digest.buffer.copyOf()
        off = digest.off
    }

    private fun mix512(s1: Array<ByteArray>, s2: Array<ByteArray>) {
        s1[0].copyInto(s2[0], 0, 12, 16)
        s1[2].copyInto(s2[0], 4, 12, 16)
        s1[1].copyInto(s2[0], 8, 12, 16)
        s1[3].copyInto(s2[0], 12, 12, 16)
        s1[2].copyInto(s2[1], 0, 0, 4)
        s1[0].copyInto(s2[1], 4, 0, 4)
        s1[3].copyInto(s2[1], 8, 0, 4)
        s1[1].copyInto(s2[1], 12, 0, 4)
        s1[2].copyInto(s2[2], 0, 4, 8)
        s1[0].copyInto(s2[2], 4, 4, 8)
        s1[3].copyInto(s2[2], 8, 4, 8)
        s1[1].copyInto(s2[2], 12, 4, 8)
        s1[0].copyInto(s2[3], 0, 8, 12)
        s1[2].copyInto(s2[3], 4, 8, 12)
        s1[1].copyInto(s2[3], 8, 8, 12)
        s1[3].copyInto(s2[3], 12, 8, 12)
    }

    @Suppress("LongMethod")
    private fun haraka512256(msg: ByteArray, out: ByteArray, outOff: Int): Int {
        val s1 = Array(4) { ByteArray(16) }
        val s2 = Array(4) { ByteArray(16) }

        // -- Unrolled version of above.
        msg.copyInto(s1[0], 0, 0, 16)
        msg.copyInto(s1[1], 0, 16, 32)
        msg.copyInto(s1[2], 0, 32, 48)
        msg.copyInto(s1[3], 0, 48, 64)

        s1[0] = aesEnc(s1[0], RC[0])
        s1[1] = aesEnc(s1[1], RC[1])
        s1[2] = aesEnc(s1[2], RC[2])
        s1[3] = aesEnc(s1[3], RC[3])
        s1[0] = aesEnc(s1[0], RC[4])
        s1[1] = aesEnc(s1[1], RC[5])
        s1[2] = aesEnc(s1[2], RC[6])
        s1[3] = aesEnc(s1[3], RC[7])
        mix512(s1, s2)
        s1[0] = aesEnc(s2[0], RC[8])
        s1[1] = aesEnc(s2[1], RC[9])
        s1[2] = aesEnc(s2[2], RC[10])
        s1[3] = aesEnc(s2[3], RC[11])
        s1[0] = aesEnc(s1[0], RC[12])
        s1[1] = aesEnc(s1[1], RC[13])
        s1[2] = aesEnc(s1[2], RC[14])
        s1[3] = aesEnc(s1[3], RC[15])
        mix512(s1, s2)
        s1[0] = aesEnc(s2[0], RC[16])
        s1[1] = aesEnc(s2[1], RC[17])
        s1[2] = aesEnc(s2[2], RC[18])
        s1[3] = aesEnc(s2[3], RC[19])
        s1[0] = aesEnc(s1[0], RC[20])
        s1[1] = aesEnc(s1[1], RC[21])
        s1[2] = aesEnc(s1[2], RC[22])
        s1[3] = aesEnc(s1[3], RC[23])
        mix512(s1, s2)
        s1[0] = aesEnc(s2[0], RC[24])
        s1[1] = aesEnc(s2[1], RC[25])
        s1[2] = aesEnc(s2[2], RC[26])
        s1[3] = aesEnc(s2[3], RC[27])
        s1[0] = aesEnc(s1[0], RC[28])
        s1[1] = aesEnc(s1[1], RC[29])
        s1[2] = aesEnc(s1[2], RC[30])
        s1[3] = aesEnc(s1[3], RC[31])
        mix512(s1, s2)
        s1[0] = aesEnc(s2[0], RC[32])
        s1[1] = aesEnc(s2[1], RC[33])
        s1[2] = aesEnc(s2[2], RC[34])
        s1[3] = aesEnc(s2[3], RC[35])
        s1[0] = aesEnc(s1[0], RC[36])
        s1[1] = aesEnc(s1[1], RC[37])
        s1[2] = aesEnc(s1[2], RC[38])
        s1[3] = aesEnc(s1[3], RC[39])
        mix512(s1, s2)
        s1[0] = xor(s2[0], msg, 0)
        s1[1] = xor(s2[1], msg, 16)
        s1[2] = xor(s2[2], msg, 32)
        s1[3] = xor(s2[3], msg, 48)
        s1[0].copyInto(out, outOff, 8, 16)
        s1[1].copyInto(out, outOff + 8, 8, 16)
        s1[2].copyInto(out, outOff + 16, 0, 8)
        s1[3].copyInto(out, outOff + 24, 0, 8)
        return digestLength
    }

    override fun update(input: Byte) {
        if (off + 1 > 64) {
            throw IllegalArgumentException("total input cannot be more than 64 bytes")
        }
        buffer[off++] = input
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        if (off + length > 64) {
            throw IllegalArgumentException("total input cannot be more than 64 bytes")
        }
        input.copyInto(buffer, off, offset, offset + length)
        off += length
    }

    override fun doFinal(out: ByteArray, outOff: Int): Int {
        if (off != 64) {
            throw IllegalStateException("input must be exactly 64 bytes")
        }
        if (out.size - outOff < 32) {
            throw IllegalArgumentException("output too short to receive digest")
        }
        val rv = haraka512256(buffer, out, outOff)
        reset()
        return rv
    }

    override fun reset() {
        off = 0
        buffer.fill(0)
    }

    companion object {
        private val RC = arrayOf(
            byteArrayOf(
                0x06.toByte(),
                0x84.toByte(),
                0x70.toByte(),
                0x4c.toByte(),
                0xe6.toByte(),
                0x20.toByte(),
                0xc0.toByte(),
                0x0a.toByte(),
                0xb2.toByte(),
                0xc5.toByte(),
                0xfe.toByte(),
                0xf0.toByte(),
                0x75.toByte(),
                0x81.toByte(),
                0x7b.toByte(),
                0x9d.toByte()
            ),
            byteArrayOf(
                0x8b.toByte(),
                0x66.toByte(),
                0xb4.toByte(),
                0xe1.toByte(),
                0x88.toByte(),
                0xf3.toByte(),
                0xa0.toByte(),
                0x6b.toByte(),
                0x64.toByte(),
                0x0f.toByte(),
                0x6b.toByte(),
                0xa4.toByte(),
                0x2f.toByte(),
                0x08.toByte(),
                0xf7.toByte(),
                0x17.toByte()
            ),
            byteArrayOf(
                0x34.toByte(),
                0x02.toByte(),
                0xde.toByte(),
                0x2d.toByte(),
                0x53.toByte(),
                0xf2.toByte(),
                0x84.toByte(),
                0x98.toByte(),
                0xcf.toByte(),
                0x02.toByte(),
                0x9d.toByte(),
                0x60.toByte(),
                0x9f.toByte(),
                0x02.toByte(),
                0x91.toByte(),
                0x14.toByte()
            ),
            byteArrayOf(
                0x0e.toByte(),
                0xd6.toByte(),
                0xea.toByte(),
                0xe6.toByte(),
                0x2e.toByte(),
                0x7b.toByte(),
                0x4f.toByte(),
                0x08.toByte(),
                0xbb.toByte(),
                0xf3.toByte(),
                0xbc.toByte(),
                0xaf.toByte(),
                0xfd.toByte(),
                0x5b.toByte(),
                0x4f.toByte(),
                0x79.toByte()
            ),
            byteArrayOf(
                0xcb.toByte(),
                0xcf.toByte(),
                0xb0.toByte(),
                0xcb.toByte(),
                0x48.toByte(),
                0x72.toByte(),
                0x44.toByte(),
                0x8b.toByte(),
                0x79.toByte(),
                0xee.toByte(),
                0xcd.toByte(),
                0x1c.toByte(),
                0xbe.toByte(),
                0x39.toByte(),
                0x70.toByte(),
                0x44.toByte()
            ),
            byteArrayOf(
                0x7e.toByte(),
                0xea.toByte(),
                0xcd.toByte(),
                0xee.toByte(),
                0x6e.toByte(),
                0x90.toByte(),
                0x32.toByte(),
                0xb7.toByte(),
                0x8d.toByte(),
                0x53.toByte(),
                0x35.toByte(),
                0xed.toByte(),
                0x2b.toByte(),
                0x8a.toByte(),
                0x05.toByte(),
                0x7b.toByte()
            ),
            byteArrayOf(
                0x67.toByte(),
                0xc2.toByte(),
                0x8f.toByte(),
                0x43.toByte(),
                0x5e.toByte(),
                0x2e.toByte(),
                0x7c.toByte(),
                0xd0.toByte(),
                0xe2.toByte(),
                0x41.toByte(),
                0x27.toByte(),
                0x61.toByte(),
                0xda.toByte(),
                0x4f.toByte(),
                0xef.toByte(),
                0x1b.toByte()
            ),
            byteArrayOf(
                0x29.toByte(),
                0x24.toByte(),
                0xd9.toByte(),
                0xb0.toByte(),
                0xaf.toByte(),
                0xca.toByte(),
                0xcc.toByte(),
                0x07.toByte(),
                0x67.toByte(),
                0x5f.toByte(),
                0xfd.toByte(),
                0xe2.toByte(),
                0x1f.toByte(),
                0xc7.toByte(),
                0x0b.toByte(),
                0x3b.toByte()
            ),
            byteArrayOf(
                0xab.toByte(),
                0x4d.toByte(),
                0x63.toByte(),
                0xf1.toByte(),
                0xe6.toByte(),
                0x86.toByte(),
                0x7f.toByte(),
                0xe9.toByte(),
                0xec.toByte(),
                0xdb.toByte(),
                0x8f.toByte(),
                0xca.toByte(),
                0xb9.toByte(),
                0xd4.toByte(),
                0x65.toByte(),
                0xee.toByte()
            ),
            byteArrayOf(
                0x1c.toByte(),
                0x30.toByte(),
                0xbf.toByte(),
                0x84.toByte(),
                0xd4.toByte(),
                0xb7.toByte(),
                0xcd.toByte(),
                0x64.toByte(),
                0x5b.toByte(),
                0x2a.toByte(),
                0x40.toByte(),
                0x4f.toByte(),
                0xad.toByte(),
                0x03.toByte(),
                0x7e.toByte(),
                0x33.toByte()
            ),
            byteArrayOf(
                0xb2.toByte(),
                0xcc.toByte(),
                0x0b.toByte(),
                0xb9.toByte(),
                0x94.toByte(),
                0x17.toByte(),
                0x23.toByte(),
                0xbf.toByte(),
                0x69.toByte(),
                0x02.toByte(),
                0x8b.toByte(),
                0x2e.toByte(),
                0x8d.toByte(),
                0xf6.toByte(),
                0x98.toByte(),
                0x00.toByte()
            ),
            byteArrayOf(
                0xfa.toByte(),
                0x04.toByte(),
                0x78.toByte(),
                0xa6.toByte(),
                0xde.toByte(),
                0x6f.toByte(),
                0x55.toByte(),
                0x72.toByte(),
                0x4a.toByte(),
                0xaa.toByte(),
                0x9e.toByte(),
                0xc8.toByte(),
                0x5c.toByte(),
                0x9d.toByte(),
                0x2d.toByte(),
                0x8a.toByte()
            ),
            byteArrayOf(
                0xdf.toByte(),
                0xb4.toByte(),
                0x9f.toByte(),
                0x2b.toByte(),
                0x6b.toByte(),
                0x77.toByte(),
                0x2a.toByte(),
                0x12.toByte(),
                0x0e.toByte(),
                0xfa.toByte(),
                0x4f.toByte(),
                0x2e.toByte(),
                0x29.toByte(),
                0x12.toByte(),
                0x9f.toByte(),
                0xd4.toByte()
            ),
            byteArrayOf(
                0x1e.toByte(),
                0xa1.toByte(),
                0x03.toByte(),
                0x44.toByte(),
                0xf4.toByte(),
                0x49.toByte(),
                0xa2.toByte(),
                0x36.toByte(),
                0x32.toByte(),
                0xd6.toByte(),
                0x11.toByte(),
                0xae.toByte(),
                0xbb.toByte(),
                0x6a.toByte(),
                0x12.toByte(),
                0xee.toByte()
            ),
            byteArrayOf(
                0xaf.toByte(),
                0x04.toByte(),
                0x49.toByte(),
                0x88.toByte(),
                0x4b.toByte(),
                0x05.toByte(),
                0x00.toByte(),
                0x84.toByte(),
                0x5f.toByte(),
                0x96.toByte(),
                0x00.toByte(),
                0xc9.toByte(),
                0x9c.toByte(),
                0xa8.toByte(),
                0xec.toByte(),
                0xa6.toByte()
            ),
            byteArrayOf(
                0x21.toByte(),
                0x02.toByte(),
                0x5e.toByte(),
                0xd8.toByte(),
                0x9d.toByte(),
                0x19.toByte(),
                0x9c.toByte(),
                0x4f.toByte(),
                0x78.toByte(),
                0xa2.toByte(),
                0xc7.toByte(),
                0xe3.toByte(),
                0x27.toByte(),
                0xe5.toByte(),
                0x93.toByte(),
                0xec.toByte()
            ),
            byteArrayOf(
                0xbf.toByte(),
                0x3a.toByte(),
                0xaa.toByte(),
                0xf8.toByte(),
                0xa7.toByte(),
                0x59.toByte(),
                0xc9.toByte(),
                0xb7.toByte(),
                0xb9.toByte(),
                0x28.toByte(),
                0x2e.toByte(),
                0xcd.toByte(),
                0x82.toByte(),
                0xd4.toByte(),
                0x01.toByte(),
                0x73.toByte()
            ),
            byteArrayOf(
                0x62.toByte(),
                0x60.toByte(),
                0x70.toByte(),
                0x0d.toByte(),
                0x61.toByte(),
                0x86.toByte(),
                0xb0.toByte(),
                0x17.toByte(),
                0x37.toByte(),
                0xf2.toByte(),
                0xef.toByte(),
                0xd9.toByte(),
                0x10.toByte(),
                0x30.toByte(),
                0x7d.toByte(),
                0x6b.toByte()
            ),
            byteArrayOf(
                0x5a.toByte(),
                0xca.toByte(),
                0x45.toByte(),
                0xc2.toByte(),
                0x21.toByte(),
                0x30.toByte(),
                0x04.toByte(),
                0x43.toByte(),
                0x81.toByte(),
                0xc2.toByte(),
                0x91.toByte(),
                0x53.toByte(),
                0xf6.toByte(),
                0xfc.toByte(),
                0x9a.toByte(),
                0xc6.toByte()
            ),
            byteArrayOf(
                0x92.toByte(),
                0x23.toByte(),
                0x97.toByte(),
                0x3c.toByte(),
                0x22.toByte(),
                0x6b.toByte(),
                0x68.toByte(),
                0xbb.toByte(),
                0x2c.toByte(),
                0xaf.toByte(),
                0x92.toByte(),
                0xe8.toByte(),
                0x36.toByte(),
                0xd1.toByte(),
                0x94.toByte(),
                0x3a.toByte()
            ),
            byteArrayOf(
                0xd3.toByte(),
                0xbf.toByte(),
                0x92.toByte(),
                0x38.toByte(),
                0x22.toByte(),
                0x58.toByte(),
                0x86.toByte(),
                0xeb.toByte(),
                0x6c.toByte(),
                0xba.toByte(),
                0xb9.toByte(),
                0x58.toByte(),
                0xe5.toByte(),
                0x10.toByte(),
                0x71.toByte(),
                0xb4.toByte()
            ),
            byteArrayOf(
                0xdb.toByte(),
                0x86.toByte(),
                0x3c.toByte(),
                0xe5.toByte(),
                0xae.toByte(),
                0xf0.toByte(),
                0xc6.toByte(),
                0x77.toByte(),
                0x93.toByte(),
                0x3d.toByte(),
                0xfd.toByte(),
                0xdd.toByte(),
                0x24.toByte(),
                0xe1.toByte(),
                0x12.toByte(),
                0x8d.toByte()
            ),
            byteArrayOf(
                0xbb.toByte(),
                0x60.toByte(),
                0x62.toByte(),
                0x68.toByte(),
                0xff.toByte(),
                0xeb.toByte(),
                0xa0.toByte(),
                0x9c.toByte(),
                0x83.toByte(),
                0xe4.toByte(),
                0x8d.toByte(),
                0xe3.toByte(),
                0xcb.toByte(),
                0x22.toByte(),
                0x12.toByte(),
                0xb1.toByte()
            ),
            byteArrayOf(
                0x73.toByte(),
                0x4b.toByte(),
                0xd3.toByte(),
                0xdc.toByte(),
                0xe2.toByte(),
                0xe4.toByte(),
                0xd1.toByte(),
                0x9c.toByte(),
                0x2d.toByte(),
                0xb9.toByte(),
                0x1a.toByte(),
                0x4e.toByte(),
                0xc7.toByte(),
                0x2b.toByte(),
                0xf7.toByte(),
                0x7d.toByte()
            ),
            byteArrayOf(
                0x43.toByte(),
                0xbb.toByte(),
                0x47.toByte(),
                0xc3.toByte(),
                0x61.toByte(),
                0x30.toByte(),
                0x1b.toByte(),
                0x43.toByte(),
                0x4b.toByte(),
                0x14.toByte(),
                0x15.toByte(),
                0xc4.toByte(),
                0x2c.toByte(),
                0xb3.toByte(),
                0x92.toByte(),
                0x4e.toByte()
            ),
            byteArrayOf(
                0xdb.toByte(),
                0xa7.toByte(),
                0x75.toByte(),
                0xa8.toByte(),
                0xe7.toByte(),
                0x07.toByte(),
                0xef.toByte(),
                0xf6.toByte(),
                0x03.toByte(),
                0xb2.toByte(),
                0x31.toByte(),
                0xdd.toByte(),
                0x16.toByte(),
                0xeb.toByte(),
                0x68.toByte(),
                0x99.toByte()
            ),
            byteArrayOf(
                0x6d.toByte(),
                0xf3.toByte(),
                0x61.toByte(),
                0x4b.toByte(),
                0x3c.toByte(),
                0x75.toByte(),
                0x59.toByte(),
                0x77.toByte(),
                0x8e.toByte(),
                0x5e.toByte(),
                0x23.toByte(),
                0x02.toByte(),
                0x7e.toByte(),
                0xca.toByte(),
                0x47.toByte(),
                0x2c.toByte()
            ),
            byteArrayOf(
                0xcd.toByte(),
                0xa7.toByte(),
                0x5a.toByte(),
                0x17.toByte(),
                0xd6.toByte(),
                0xde.toByte(),
                0x7d.toByte(),
                0x77.toByte(),
                0x6d.toByte(),
                0x1b.toByte(),
                0xe5.toByte(),
                0xb9.toByte(),
                0xb8.toByte(),
                0x86.toByte(),
                0x17.toByte(),
                0xf9.toByte()
            ),
            byteArrayOf(
                0xec.toByte(),
                0x6b.toByte(),
                0x43.toByte(),
                0xf0.toByte(),
                0x6b.toByte(),
                0xa8.toByte(),
                0xe9.toByte(),
                0xaa.toByte(),
                0x9d.toByte(),
                0x6c.toByte(),
                0x06.toByte(),
                0x9d.toByte(),
                0xa9.toByte(),
                0x46.toByte(),
                0xee.toByte(),
                0x5d.toByte()
            ),
            byteArrayOf(
                0xcb.toByte(),
                0x1e.toByte(),
                0x69.toByte(),
                0x50.toByte(),
                0xf9.toByte(),
                0x57.toByte(),
                0x33.toByte(),
                0x2b.toByte(),
                0xa2.toByte(),
                0x53.toByte(),
                0x11.toByte(),
                0x59.toByte(),
                0x3b.toByte(),
                0xf3.toByte(),
                0x27.toByte(),
                0xc1.toByte()
            ),
            byteArrayOf(
                0x2c.toByte(),
                0xee.toByte(),
                0x0c.toByte(),
                0x75.toByte(),
                0x00.toByte(),
                0xda.toByte(),
                0x61.toByte(),
                0x9c.toByte(),
                0xe4.toByte(),
                0xed.toByte(),
                0x03.toByte(),
                0x53.toByte(),
                0x60.toByte(),
                0x0e.toByte(),
                0xd0.toByte(),
                0xd9.toByte()
            ),
            byteArrayOf(
                0xf0.toByte(),
                0xb1.toByte(),
                0xa5.toByte(),
                0xa1.toByte(),
                0x96.toByte(),
                0xe9.toByte(),
                0x0c.toByte(),
                0xab.toByte(),
                0x80.toByte(),
                0xbb.toByte(),
                0xba.toByte(),
                0xbc.toByte(),
                0x63.toByte(),
                0xa4.toByte(),
                0xa3.toByte(),
                0x50.toByte()
            ),
            byteArrayOf(
                0xae.toByte(),
                0x3d.toByte(),
                0xb1.toByte(),
                0x02.toByte(),
                0x5e.toByte(),
                0x96.toByte(),
                0x29.toByte(),
                0x88.toByte(),
                0xab.toByte(),
                0x0d.toByte(),
                0xde.toByte(),
                0x30.toByte(),
                0x93.toByte(),
                0x8d.toByte(),
                0xca.toByte(),
                0x39.toByte()
            ),
            byteArrayOf(
                0x17.toByte(),
                0xbb.toByte(),
                0x8f.toByte(),
                0x38.toByte(),
                0xd5.toByte(),
                0x54.toByte(),
                0xa4.toByte(),
                0x0b.toByte(),
                0x88.toByte(),
                0x14.toByte(),
                0xf3.toByte(),
                0xa8.toByte(),
                0x2e.toByte(),
                0x75.toByte(),
                0xb4.toByte(),
                0x42.toByte()
            ),
            byteArrayOf(
                0x34.toByte(),
                0xbb.toByte(),
                0x8a.toByte(),
                0x5b.toByte(),
                0x5f.toByte(),
                0x42.toByte(),
                0x7f.toByte(),
                0xd7.toByte(),
                0xae.toByte(),
                0xb6.toByte(),
                0xb7.toByte(),
                0x79.toByte(),
                0x36.toByte(),
                0x0a.toByte(),
                0x16.toByte(),
                0xf6.toByte()
            ),
            byteArrayOf(
                0x26.toByte(),
                0xf6.toByte(),
                0x52.toByte(),
                0x41.toByte(),
                0xcb.toByte(),
                0xe5.toByte(),
                0x54.toByte(),
                0x38.toByte(),
                0x43.toByte(),
                0xce.toByte(),
                0x59.toByte(),
                0x18.toByte(),
                0xff.toByte(),
                0xba.toByte(),
                0xaf.toByte(),
                0xde.toByte()
            ),
            byteArrayOf(
                0x4c.toByte(),
                0xe9.toByte(),
                0x9a.toByte(),
                0x54.toByte(),
                0xb9.toByte(),
                0xf3.toByte(),
                0x02.toByte(),
                0x6a.toByte(),
                0xa2.toByte(),
                0xca.toByte(),
                0x9c.toByte(),
                0xf7.toByte(),
                0x83.toByte(),
                0x9e.toByte(),
                0xc9.toByte(),
                0x78.toByte()
            ),
            byteArrayOf(
                0xae.toByte(),
                0x51.toByte(),
                0xa5.toByte(),
                0x1a.toByte(),
                0x1b.toByte(),
                0xdf.toByte(),
                0xf7.toByte(),
                0xbe.toByte(),
                0x40.toByte(),
                0xc0.toByte(),
                0x6e.toByte(),
                0x28.toByte(),
                0x22.toByte(),
                0x90.toByte(),
                0x12.toByte(),
                0x35.toByte()
            ),
            byteArrayOf(
                0xa0.toByte(),
                0xc1.toByte(),
                0x61.toByte(),
                0x3c.toByte(),
                0xba.toByte(),
                0x7e.toByte(),
                0xd2.toByte(),
                0x2b.toByte(),
                0xc1.toByte(),
                0x73.toByte(),
                0xbc.toByte(),
                0x0f.toByte(),
                0x48.toByte(),
                0xa6.toByte(),
                0x59.toByte(),
                0xcf.toByte()
            ),
            byteArrayOf(
                0x75.toByte(),
                0x6a.toByte(),
                0xcc.toByte(),
                0x03.toByte(),
                0x02.toByte(),
                0x28.toByte(),
                0x82.toByte(),
                0x88.toByte(),
                0x4a.toByte(),
                0xd6.toByte(),
                0xbd.toByte(),
                0xfd.toByte(),
                0xe9.toByte(),
                0xc5.toByte(),
                0x9d.toByte(),
                0xa1.toByte()
            )
        )
    }

    override fun copy() = Haraka512_256(this)

    override val blockLength: Int
        get() = 64

    override fun toString() = Algorithm.Haraka512_256.algorithmName
}
