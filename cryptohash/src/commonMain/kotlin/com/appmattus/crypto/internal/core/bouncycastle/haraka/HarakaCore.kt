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

import com.appmattus.crypto.Digest

/**
 * Base class for Haraka v2, https://eprint.iacr.org/2016/098.pdf
 */
@Suppress("MagicNumber")
internal abstract class HarakaCore<D : HarakaCore<D>> : Digest<D> {

    abstract fun doFinal(out: ByteArray, outOff: Int): Int

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        doFinal(digest, 0)
        return digest
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

    override val digestLength: Int
        get() = 32

    companion object {

        private val S = arrayOf(
            byteArrayOf(
                0x63.toByte(),
                0x7c.toByte(),
                0x77.toByte(),
                0x7b.toByte(),
                0xf2.toByte(),
                0x6b.toByte(),
                0x6f.toByte(),
                0xc5.toByte(),
                0x30.toByte(),
                0x01.toByte(),
                0x67.toByte(),
                0x2b.toByte(),
                0xfe.toByte(),
                0xd7.toByte(),
                0xab.toByte(),
                0x76.toByte()
            ),
            byteArrayOf(
                0xca.toByte(),
                0x82.toByte(),
                0xc9.toByte(),
                0x7d.toByte(),
                0xfa.toByte(),
                0x59.toByte(),
                0x47.toByte(),
                0xf0.toByte(),
                0xad.toByte(),
                0xd4.toByte(),
                0xa2.toByte(),
                0xaf.toByte(),
                0x9c.toByte(),
                0xa4.toByte(),
                0x72.toByte(),
                0xc0.toByte()
            ),
            byteArrayOf(
                0xb7.toByte(),
                0xfd.toByte(),
                0x93.toByte(),
                0x26.toByte(),
                0x36.toByte(),
                0x3f.toByte(),
                0xf7.toByte(),
                0xcc.toByte(),
                0x34.toByte(),
                0xa5.toByte(),
                0xe5.toByte(),
                0xf1.toByte(),
                0x71.toByte(),
                0xd8.toByte(),
                0x31.toByte(),
                0x15.toByte()
            ),
            byteArrayOf(
                0x04.toByte(),
                0xc7.toByte(),
                0x23.toByte(),
                0xc3.toByte(),
                0x18.toByte(),
                0x96.toByte(),
                0x05.toByte(),
                0x9a.toByte(),
                0x07.toByte(),
                0x12.toByte(),
                0x80.toByte(),
                0xe2.toByte(),
                0xeb.toByte(),
                0x27.toByte(),
                0xb2.toByte(),
                0x75.toByte()
            ),
            byteArrayOf(
                0x09.toByte(),
                0x83.toByte(),
                0x2c.toByte(),
                0x1a.toByte(),
                0x1b.toByte(),
                0x6e.toByte(),
                0x5a.toByte(),
                0xa0.toByte(),
                0x52.toByte(),
                0x3b.toByte(),
                0xd6.toByte(),
                0xb3.toByte(),
                0x29.toByte(),
                0xe3.toByte(),
                0x2f.toByte(),
                0x84.toByte()
            ),
            byteArrayOf(
                0x53.toByte(),
                0xd1.toByte(),
                0x00.toByte(),
                0xed.toByte(),
                0x20.toByte(),
                0xfc.toByte(),
                0xb1.toByte(),
                0x5b.toByte(),
                0x6a.toByte(),
                0xcb.toByte(),
                0xbe.toByte(),
                0x39.toByte(),
                0x4a.toByte(),
                0x4c.toByte(),
                0x58.toByte(),
                0xcf.toByte()
            ),
            byteArrayOf(
                0xd0.toByte(),
                0xef.toByte(),
                0xaa.toByte(),
                0xfb.toByte(),
                0x43.toByte(),
                0x4d.toByte(),
                0x33.toByte(),
                0x85.toByte(),
                0x45.toByte(),
                0xf9.toByte(),
                0x02.toByte(),
                0x7f.toByte(),
                0x50.toByte(),
                0x3c.toByte(),
                0x9f.toByte(),
                0xa8.toByte()
            ),
            byteArrayOf(
                0x51.toByte(),
                0xa3.toByte(),
                0x40.toByte(),
                0x8f.toByte(),
                0x92.toByte(),
                0x9d.toByte(),
                0x38.toByte(),
                0xf5.toByte(),
                0xbc.toByte(),
                0xb6.toByte(),
                0xda.toByte(),
                0x21.toByte(),
                0x10.toByte(),
                0xff.toByte(),
                0xf3.toByte(),
                0xd2.toByte()
            ),
            byteArrayOf(
                0xcd.toByte(),
                0x0c.toByte(),
                0x13.toByte(),
                0xec.toByte(),
                0x5f.toByte(),
                0x97.toByte(),
                0x44.toByte(),
                0x17.toByte(),
                0xc4.toByte(),
                0xa7.toByte(),
                0x7e.toByte(),
                0x3d.toByte(),
                0x64.toByte(),
                0x5d.toByte(),
                0x19.toByte(),
                0x73.toByte()
            ),
            byteArrayOf(
                0x60.toByte(),
                0x81.toByte(),
                0x4f.toByte(),
                0xdc.toByte(),
                0x22.toByte(),
                0x2a.toByte(),
                0x90.toByte(),
                0x88.toByte(),
                0x46.toByte(),
                0xee.toByte(),
                0xb8.toByte(),
                0x14.toByte(),
                0xde.toByte(),
                0x5e.toByte(),
                0x0b.toByte(),
                0xdb.toByte()
            ),
            byteArrayOf(
                0xe0.toByte(),
                0x32.toByte(),
                0x3a.toByte(),
                0x0a.toByte(),
                0x49.toByte(),
                0x06.toByte(),
                0x24.toByte(),
                0x5c.toByte(),
                0xc2.toByte(),
                0xd3.toByte(),
                0xac.toByte(),
                0x62.toByte(),
                0x91.toByte(),
                0x95.toByte(),
                0xe4.toByte(),
                0x79.toByte()
            ),
            byteArrayOf(
                0xe7.toByte(),
                0xc8.toByte(),
                0x37.toByte(),
                0x6d.toByte(),
                0x8d.toByte(),
                0xd5.toByte(),
                0x4e.toByte(),
                0xa9.toByte(),
                0x6c.toByte(),
                0x56.toByte(),
                0xf4.toByte(),
                0xea.toByte(),
                0x65.toByte(),
                0x7a.toByte(),
                0xae.toByte(),
                0x08.toByte()
            ),
            byteArrayOf(
                0xba.toByte(),
                0x78.toByte(),
                0x25.toByte(),
                0x2e.toByte(),
                0x1c.toByte(),
                0xa6.toByte(),
                0xb4.toByte(),
                0xc6.toByte(),
                0xe8.toByte(),
                0xdd.toByte(),
                0x74.toByte(),
                0x1f.toByte(),
                0x4b.toByte(),
                0xbd.toByte(),
                0x8b.toByte(),
                0x8a.toByte()
            ),
            byteArrayOf(
                0x70.toByte(),
                0x3e.toByte(),
                0xb5.toByte(),
                0x66.toByte(),
                0x48.toByte(),
                0x03.toByte(),
                0xf6.toByte(),
                0x0e.toByte(),
                0x61.toByte(),
                0x35.toByte(),
                0x57.toByte(),
                0xb9.toByte(),
                0x86.toByte(),
                0xc1.toByte(),
                0x1d.toByte(),
                0x9e.toByte()
            ),
            byteArrayOf(
                0xe1.toByte(),
                0xf8.toByte(),
                0x98.toByte(),
                0x11.toByte(),
                0x69.toByte(),
                0xd9.toByte(),
                0x8e.toByte(),
                0x94.toByte(),
                0x9b.toByte(),
                0x1e.toByte(),
                0x87.toByte(),
                0xe9.toByte(),
                0xce.toByte(),
                0x55.toByte(),
                0x28.toByte(),
                0xdf.toByte()
            ),
            byteArrayOf(
                0x8c.toByte(),
                0xa1.toByte(),
                0x89.toByte(),
                0x0d.toByte(),
                0xbf.toByte(),
                0xe6.toByte(),
                0x42.toByte(),
                0x68.toByte(),
                0x41.toByte(),
                0x99.toByte(),
                0x2d.toByte(),
                0x0f.toByte(),
                0xb0.toByte(),
                0x54.toByte(),
                0xbb.toByte(),
                0x16.toByte()
            )
        )

        private fun sBox(x: Byte): Byte {
            return S[x.toInt() and 0xFF ushr 4][x.toInt() and 0xF]
        }

        private fun subBytes(s: ByteArray): ByteArray {
            val out = ByteArray(s.size)
            out[0] = sBox(s[0])
            out[1] = sBox(s[1])
            out[2] = sBox(s[2])
            out[3] = sBox(s[3])
            out[4] = sBox(s[4])
            out[5] = sBox(s[5])
            out[6] = sBox(s[6])
            out[7] = sBox(s[7])
            out[8] = sBox(s[8])
            out[9] = sBox(s[9])
            out[10] = sBox(s[10])
            out[11] = sBox(s[11])
            out[12] = sBox(s[12])
            out[13] = sBox(s[13])
            out[14] = sBox(s[14])
            out[15] = sBox(s[15])
            return out
        }

        private fun shiftRows(s: ByteArray): ByteArray {
            return byteArrayOf(
                s[0], s[5], s[10], s[15],
                s[4], s[9], s[14], s[3],
                s[8], s[13], s[2], s[7],
                s[12], s[1], s[6], s[11]
            )
        }

        @Suppress("NAME_SHADOWING")
        fun aesEnc(s: ByteArray, rk: ByteArray): ByteArray {
            var s = s
            s = subBytes(s)
            s = shiftRows(s)
            s = mixColumns(s)
            xorReverse(s, rk)
            return s
        }

        private fun xTime(x: Byte): Byte {
            return if (x.toInt() ushr 7 > 0) {
                (x.toInt() shl 1 xor 0x1b and 0xff)
            } else {
                (x.toInt() shl 1 and 0xff)
            }.toByte()
        }

        private fun xorReverse(x: ByteArray, y: ByteArray) {
            x[0] = (x[0].toInt() xor y[15].toInt()).toByte()
            x[1] = (x[1].toInt() xor y[14].toInt()).toByte()
            x[2] = (x[2].toInt() xor y[13].toInt()).toByte()
            x[3] = (x[3].toInt() xor y[12].toInt()).toByte()
            x[4] = (x[4].toInt() xor y[11].toInt()).toByte()
            x[5] = (x[5].toInt() xor y[10].toInt()).toByte()
            x[6] = (x[6].toInt() xor y[9].toInt()).toByte()
            x[7] = (x[7].toInt() xor y[8].toInt()).toByte()
            x[8] = (x[8].toInt() xor y[7].toInt()).toByte()
            x[9] = (x[9].toInt() xor y[6].toInt()).toByte()
            x[10] = (x[10].toInt() xor y[5].toInt()).toByte()
            x[11] = (x[11].toInt() xor y[4].toInt()).toByte()
            x[12] = (x[12].toInt() xor y[3].toInt()).toByte()
            x[13] = (x[13].toInt() xor y[2].toInt()).toByte()
            x[14] = (x[14].toInt() xor y[1].toInt()).toByte()
            x[15] = (x[15].toInt() xor y[0].toInt()).toByte()
        }

        @Suppress("NAME_SHADOWING")
        fun xor(x: ByteArray, y: ByteArray, yStart: Int): ByteArray {
            var yStart = yStart
            val out = ByteArray(16)
            for (i in out.indices) {
                out[i] = (x[i].toInt() xor y[yStart++].toInt()).toByte()
            }
            return out
        }

        private fun mixColumns(s: ByteArray): ByteArray {
            val out = ByteArray(s.size)
            var j = 0
            for (i in 0..3) {
                out[j++] = (xTime(s[4 * i]).toInt() xor xTime(
                    s[4 * i + 1]
                ).toInt() xor s[4 * i + 1].toInt() xor s[4 * i + 2].toInt() xor s[4 * i + 3].toInt()).toByte()
                out[j++] = (s[4 * i].toInt() xor xTime(s[4 * i + 1]).toInt() xor xTime(
                    s[4 * i + 2]
                ).toInt() xor s[4 * i + 2].toInt() xor s[4 * i + 3].toInt()).toByte()
                out[j++] = (s[4 * i].toInt() xor s[4 * i + 1].toInt() xor xTime(s[4 * i + 2]).toInt() xor xTime(
                    s[4 * i + 3]
                ).toInt() xor s[4 * i + 3].toInt()).toByte()
                out[j++] = (xTime(s[4 * i]).toInt() xor s[4 * i].toInt() xor s[4 * i + 1].toInt() xor s[4 * i + 2].toInt() xor xTime(
                    s[4 * i + 3]
                ).toInt()).toByte()
            }
            return out
        }
    }
}
