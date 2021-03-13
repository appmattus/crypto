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

import com.appmattus.crypto.Digest

/**
 * This class implements Hamsi-224 and Hamsi-256.
 *
 * @version $Revision: 239 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("TooManyFunctions", "MagicNumber", "LargeClass")
internal abstract class HamsiSmallCore<D : HamsiSmallCore<D>> : Digest<D> {
    private val h: IntArray = IntArray(8)
    private var bitCount: Long = 0
    private var partial = 0
    private var partialLen = 0

    init {
        reset()
    }

    override fun update(input: Byte) {
        bitCount += 8
        partial = partial shl 8 or (input.toInt() and 0xFF)
        partialLen++
        if (partialLen == 4) {
            process(
                partial ushr 24, partial ushr 16 and 0xFF,
                partial ushr 8 and 0xFF, partial and 0xFF
            )
            partialLen = 0
        }
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    @Suppress("NAME_SHADOWING")
    override fun update(input: ByteArray, offset: Int, length: Int) {
        var off = offset
        var len = length
        bitCount += len.toLong() shl 3
        if (partialLen != 0) {
            while (partialLen < 4 && len > 0) {
                partial = (partial shl 8
                        or (input[off++].toInt() and 0xFF))
                partialLen++
                len--
            }
            if (partialLen < 4) return
            process(
                partial ushr 24, partial ushr 16 and 0xFF,
                partial ushr 8 and 0xFF, partial and 0xFF
            )
            partialLen = 0
        }
        while (len >= 4) {
            process(
                input[off + 0].toInt() and 0xFF,
                input[off + 1].toInt() and 0xFF,
                input[off + 2].toInt() and 0xFF,
                input[off + 3].toInt() and 0xFF
            )
            off += 4
            len -= 4
        }
        partialLen = len
        while (len-- > 0) partial = partial shl 8 or (input[off++].toInt() and 0xFF)
    }

    override fun digest(): ByteArray {
        val n = digestLength
        val out = ByteArray(n)
        digest(out, 0, n)
        return out
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input, 0, input.size)
        return digest()
    }

    @Suppress("NAME_SHADOWING")
    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        var len = length
        val bitCount = bitCount
        update(0x80.toByte())
        while (partialLen != 0) update(0x00.toByte())
        process(
            (bitCount ushr 56).toInt() and 0xFF,
            (bitCount ushr 48).toInt() and 0xFF,
            (bitCount ushr 40).toInt() and 0xFF,
            (bitCount ushr 32).toInt() and 0xFF
        )
        processFinal(
            bitCount.toInt() ushr 24 and 0xFF,
            bitCount.toInt() ushr 16 and 0xFF,
            bitCount.toInt() ushr 8 and 0xFF,
            bitCount.toInt() and 0xFF
        )
        val n = digestLength
        if (len > n) len = n
        var ch = 0
        var i = 0
        var j = 0
        while (i < len) {
            if (i and 3 == 0) ch = h[j++]
            output[offset + i] = (ch ushr 24).toByte()
            ch = ch shl 8
            i++
        }
        reset()
        return len
    }

    override fun reset() {
        iV.copyInto(h, 0, 0, h.size)
        bitCount = 0
        partialLen = 0
    }

    override fun copy(): D {
        val d = dup()
        h.copyInto(d.h, 0, 0, h.size)
        d.bitCount = bitCount
        d.partial = partial
        d.partialLen = partialLen
        return d
    }

    /*
     * Private communication from Hamsi designer Ozgul Kucuk:
     *
     * << For HMAC you can calculate B = 256*ceil(k / 256)
     *    (same as CubeHash). >>
     */
    override val blockLength: Int
        get() = 32

    /**
     * Get the IV.
     *
     * @return the IV (initial values for the state words)
     */
    protected abstract val iV: IntArray

    /**
     * Create a new instance of the same runtime class than this object.
     *
     * @return the duplicate
     */
    protected abstract fun dup(): D

    @Suppress("JoinDeclarationAndAssignment", "LongMethod")
    private fun process(b0: Int, b1: Int, b2: Int, b3: Int) {
        var rp = T256_0[b0]
        var m0 = rp[0]
        var m1 = rp[1]
        var m2 = rp[2]
        var m3 = rp[3]
        var m4 = rp[4]
        var m5 = rp[5]
        var m6 = rp[6]
        var m7 = rp[7]
        rp = T256_1[b1]
        m0 = m0 xor rp[0]
        m1 = m1 xor rp[1]
        m2 = m2 xor rp[2]
        m3 = m3 xor rp[3]
        m4 = m4 xor rp[4]
        m5 = m5 xor rp[5]
        m6 = m6 xor rp[6]
        m7 = m7 xor rp[7]
        rp = T256_2[b2]
        m0 = m0 xor rp[0]
        m1 = m1 xor rp[1]
        m2 = m2 xor rp[2]
        m3 = m3 xor rp[3]
        m4 = m4 xor rp[4]
        m5 = m5 xor rp[5]
        m6 = m6 xor rp[6]
        m7 = m7 xor rp[7]
        rp = T256_3[b3]
        m0 = m0 xor rp[0]
        m1 = m1 xor rp[1]
        m2 = m2 xor rp[2]
        m3 = m3 xor rp[3]
        m4 = m4 xor rp[4]
        m5 = m5 xor rp[5]
        m6 = m6 xor rp[6]
        m7 = m7 xor rp[7]
        var c0 = h[0]
        var c1 = h[1]
        var c2 = h[2]
        var c3 = h[3]
        var c4 = h[4]
        var c5 = h[5]
        var c6 = h[6]
        var c7 = h[7]
        var t: Int
        m0 = m0 xor ALPHA_N[0x00]
        m1 = m1 xor (ALPHA_N[0x01] xor 0)
        c0 = c0 xor ALPHA_N[0x02]
        c1 = c1 xor ALPHA_N[0x03]
        c2 = c2 xor ALPHA_N[0x08]
        c3 = c3 xor ALPHA_N[0x09]
        m2 = m2 xor ALPHA_N[0x0A]
        m3 = m3 xor ALPHA_N[0x0B]
        m4 = m4 xor ALPHA_N[0x10]
        m5 = m5 xor ALPHA_N[0x11]
        c4 = c4 xor ALPHA_N[0x12]
        c5 = c5 xor ALPHA_N[0x13]
        c6 = c6 xor ALPHA_N[0x18]
        c7 = c7 xor ALPHA_N[0x19]
        m6 = m6 xor ALPHA_N[0x1A]
        m7 = m7 xor ALPHA_N[0x1B]
        t = m0
        m0 = m0 and m4
        m0 = m0 xor c6
        m4 = m4 xor c2
        m4 = m4 xor m0
        c6 = c6 or t
        c6 = c6 xor c2
        t = t xor m4
        c2 = c6
        c6 = c6 or t
        c6 = c6 xor m0
        m0 = m0 and c2
        t = t xor m0
        c2 = c2 xor c6
        c2 = c2 xor t
        m0 = m4
        m4 = c2
        c2 = c6
        c6 = t.inv()
        t = m1
        m1 = m1 and m5
        m1 = m1 xor c7
        m5 = m5 xor c3
        m5 = m5 xor m1
        c7 = c7 or t
        c7 = c7 xor c3
        t = t xor m5
        c3 = c7
        c7 = c7 or t
        c7 = c7 xor m1
        m1 = m1 and c3
        t = t xor m1
        c3 = c3 xor c7
        c3 = c3 xor t
        m1 = m5
        m5 = c3
        c3 = c7
        c7 = t.inv()
        t = c0
        c0 = c0 and c4
        c0 = c0 xor m6
        c4 = c4 xor m2
        c4 = c4 xor c0
        m6 = m6 or t
        m6 = m6 xor m2
        t = t xor c4
        m2 = m6
        m6 = m6 or t
        m6 = m6 xor c0
        c0 = c0 and m2
        t = t xor c0
        m2 = m2 xor m6
        m2 = m2 xor t
        c0 = c4
        c4 = m2
        m2 = m6
        m6 = t.inv()
        t = c1
        c1 = c1 and c5
        c1 = c1 xor m7
        c5 = c5 xor m3
        c5 = c5 xor c1
        m7 = m7 or t
        m7 = m7 xor m3
        t = t xor c5
        m3 = m7
        m7 = m7 or t
        m7 = m7 xor c1
        c1 = c1 and m3
        t = t xor c1
        m3 = m3 xor m7
        m3 = m3 xor t
        c1 = c5
        c5 = m3
        m3 = m7
        m7 = t.inv()
        m0 = m0 shl 13 or (m0 ushr 32 - 13)
        c4 = c4 shl 3 or (c4 ushr 32 - 3)
        c3 = c3 xor (m0 xor c4)
        m7 = m7 xor (c4 xor (m0 shl 3))
        c3 = c3 shl 1 or (c3 ushr 32 - 1)
        m7 = m7 shl 7 or (m7 ushr 32 - 7)
        m0 = m0 xor (c3 xor m7)
        c4 = c4 xor (m7 xor (c3 shl 7))
        m0 = m0 shl 5 or (m0 ushr 32 - 5)
        c4 = c4 shl 22 or (c4 ushr 32 - 22)
        m1 = m1 shl 13 or (m1 ushr 32 - 13)
        c5 = c5 shl 3 or (c5 ushr 32 - 3)
        m2 = m2 xor (m1 xor c5)
        c6 = c6 xor (c5 xor (m1 shl 3))
        m2 = m2 shl 1 or (m2 ushr 32 - 1)
        c6 = c6 shl 7 or (c6 ushr 32 - 7)
        m1 = m1 xor (m2 xor c6)
        c5 = c5 xor (c6 xor (m2 shl 7))
        m1 = m1 shl 5 or (m1 ushr 32 - 5)
        c5 = c5 shl 22 or (c5 ushr 32 - 22)
        c0 = c0 shl 13 or (c0 ushr 32 - 13)
        m4 = m4 shl 3 or (m4 ushr 32 - 3)
        m3 = m3 xor (c0 xor m4)
        c7 = c7 xor (m4 xor (c0 shl 3))
        m3 = m3 shl 1 or (m3 ushr 32 - 1)
        c7 = c7 shl 7 or (c7 ushr 32 - 7)
        c0 = c0 xor (m3 xor c7)
        m4 = m4 xor (c7 xor (m3 shl 7))
        c0 = c0 shl 5 or (c0 ushr 32 - 5)
        m4 = m4 shl 22 or (m4 ushr 32 - 22)
        c1 = c1 shl 13 or (c1 ushr 32 - 13)
        m5 = m5 shl 3 or (m5 ushr 32 - 3)
        c2 = c2 xor (c1 xor m5)
        m6 = m6 xor (m5 xor (c1 shl 3))
        c2 = c2 shl 1 or (c2 ushr 32 - 1)
        m6 = m6 shl 7 or (m6 ushr 32 - 7)
        c1 = c1 xor (c2 xor m6)
        m5 = m5 xor (m6 xor (c2 shl 7))
        c1 = c1 shl 5 or (c1 ushr 32 - 5)
        m5 = m5 shl 22 or (m5 ushr 32 - 22)
        m0 = m0 xor ALPHA_N[0x00]
        m1 = m1 xor (ALPHA_N[0x01] xor 1)
        c0 = c0 xor ALPHA_N[0x02]
        c1 = c1 xor ALPHA_N[0x03]
        c2 = c2 xor ALPHA_N[0x08]
        c3 = c3 xor ALPHA_N[0x09]
        m2 = m2 xor ALPHA_N[0x0A]
        m3 = m3 xor ALPHA_N[0x0B]
        m4 = m4 xor ALPHA_N[0x10]
        m5 = m5 xor ALPHA_N[0x11]
        c4 = c4 xor ALPHA_N[0x12]
        c5 = c5 xor ALPHA_N[0x13]
        c6 = c6 xor ALPHA_N[0x18]
        c7 = c7 xor ALPHA_N[0x19]
        m6 = m6 xor ALPHA_N[0x1A]
        m7 = m7 xor ALPHA_N[0x1B]
        t = m0
        m0 = m0 and m4
        m0 = m0 xor c6
        m4 = m4 xor c2
        m4 = m4 xor m0
        c6 = c6 or t
        c6 = c6 xor c2
        t = t xor m4
        c2 = c6
        c6 = c6 or t
        c6 = c6 xor m0
        m0 = m0 and c2
        t = t xor m0
        c2 = c2 xor c6
        c2 = c2 xor t
        m0 = m4
        m4 = c2
        c2 = c6
        c6 = t.inv()
        t = m1
        m1 = m1 and m5
        m1 = m1 xor c7
        m5 = m5 xor c3
        m5 = m5 xor m1
        c7 = c7 or t
        c7 = c7 xor c3
        t = t xor m5
        c3 = c7
        c7 = c7 or t
        c7 = c7 xor m1
        m1 = m1 and c3
        t = t xor m1
        c3 = c3 xor c7
        c3 = c3 xor t
        m1 = m5
        m5 = c3
        c3 = c7
        c7 = t.inv()
        t = c0
        c0 = c0 and c4
        c0 = c0 xor m6
        c4 = c4 xor m2
        c4 = c4 xor c0
        m6 = m6 or t
        m6 = m6 xor m2
        t = t xor c4
        m2 = m6
        m6 = m6 or t
        m6 = m6 xor c0
        c0 = c0 and m2
        t = t xor c0
        m2 = m2 xor m6
        m2 = m2 xor t
        c0 = c4
        c4 = m2
        m2 = m6
        m6 = t.inv()
        t = c1
        c1 = c1 and c5
        c1 = c1 xor m7
        c5 = c5 xor m3
        c5 = c5 xor c1
        m7 = m7 or t
        m7 = m7 xor m3
        t = t xor c5
        m3 = m7
        m7 = m7 or t
        m7 = m7 xor c1
        c1 = c1 and m3
        t = t xor c1
        m3 = m3 xor m7
        m3 = m3 xor t
        c1 = c5
        c5 = m3
        m3 = m7
        m7 = t.inv()
        m0 = m0 shl 13 or (m0 ushr 32 - 13)
        c4 = c4 shl 3 or (c4 ushr 32 - 3)
        c3 = c3 xor (m0 xor c4)
        m7 = m7 xor (c4 xor (m0 shl 3))
        c3 = c3 shl 1 or (c3 ushr 32 - 1)
        m7 = m7 shl 7 or (m7 ushr 32 - 7)
        m0 = m0 xor (c3 xor m7)
        c4 = c4 xor (m7 xor (c3 shl 7))
        m0 = m0 shl 5 or (m0 ushr 32 - 5)
        c4 = c4 shl 22 or (c4 ushr 32 - 22)
        m1 = m1 shl 13 or (m1 ushr 32 - 13)
        c5 = c5 shl 3 or (c5 ushr 32 - 3)
        m2 = m2 xor (m1 xor c5)
        c6 = c6 xor (c5 xor (m1 shl 3))
        m2 = m2 shl 1 or (m2 ushr 32 - 1)
        c6 = c6 shl 7 or (c6 ushr 32 - 7)
        m1 = m1 xor (m2 xor c6)
        c5 = c5 xor (c6 xor (m2 shl 7))
        m1 = m1 shl 5 or (m1 ushr 32 - 5)
        c5 = c5 shl 22 or (c5 ushr 32 - 22)
        c0 = c0 shl 13 or (c0 ushr 32 - 13)
        m4 = m4 shl 3 or (m4 ushr 32 - 3)
        m3 = m3 xor (c0 xor m4)
        c7 = c7 xor (m4 xor (c0 shl 3))
        m3 = m3 shl 1 or (m3 ushr 32 - 1)
        c7 = c7 shl 7 or (c7 ushr 32 - 7)
        c0 = c0 xor (m3 xor c7)
        m4 = m4 xor (c7 xor (m3 shl 7))
        c0 = c0 shl 5 or (c0 ushr 32 - 5)
        m4 = m4 shl 22 or (m4 ushr 32 - 22)
        c1 = c1 shl 13 or (c1 ushr 32 - 13)
        m5 = m5 shl 3 or (m5 ushr 32 - 3)
        c2 = c2 xor (c1 xor m5)
        m6 = m6 xor (m5 xor (c1 shl 3))
        c2 = c2 shl 1 or (c2 ushr 32 - 1)
        m6 = m6 shl 7 or (m6 ushr 32 - 7)
        c1 = c1 xor (c2 xor m6)
        m5 = m5 xor (m6 xor (c2 shl 7))
        c1 = c1 shl 5 or (c1 ushr 32 - 5)
        m5 = m5 shl 22 or (m5 ushr 32 - 22)
        m0 = m0 xor ALPHA_N[0x00]
        m1 = m1 xor (ALPHA_N[0x01] xor 2)
        c0 = c0 xor ALPHA_N[0x02]
        c1 = c1 xor ALPHA_N[0x03]
        c2 = c2 xor ALPHA_N[0x08]
        c3 = c3 xor ALPHA_N[0x09]
        m2 = m2 xor ALPHA_N[0x0A]
        m3 = m3 xor ALPHA_N[0x0B]
        m4 = m4 xor ALPHA_N[0x10]
        m5 = m5 xor ALPHA_N[0x11]
        c4 = c4 xor ALPHA_N[0x12]
        c5 = c5 xor ALPHA_N[0x13]
        c6 = c6 xor ALPHA_N[0x18]
        c7 = c7 xor ALPHA_N[0x19]
        m6 = m6 xor ALPHA_N[0x1A]
        m7 = m7 xor ALPHA_N[0x1B]
        t = m0
        m0 = m0 and m4
        m0 = m0 xor c6
        m4 = m4 xor c2
        m4 = m4 xor m0
        c6 = c6 or t
        c6 = c6 xor c2
        t = t xor m4
        c2 = c6
        c6 = c6 or t
        c6 = c6 xor m0
        m0 = m0 and c2
        t = t xor m0
        c2 = c2 xor c6
        c2 = c2 xor t
        m0 = m4
        m4 = c2
        c2 = c6
        c6 = t.inv()
        t = m1
        m1 = m1 and m5
        m1 = m1 xor c7
        m5 = m5 xor c3
        m5 = m5 xor m1
        c7 = c7 or t
        c7 = c7 xor c3
        t = t xor m5
        c3 = c7
        c7 = c7 or t
        c7 = c7 xor m1
        m1 = m1 and c3
        t = t xor m1
        c3 = c3 xor c7
        c3 = c3 xor t
        m1 = m5
        m5 = c3
        c3 = c7
        c7 = t.inv()
        t = c0
        c0 = c0 and c4
        c0 = c0 xor m6
        c4 = c4 xor m2
        c4 = c4 xor c0
        m6 = m6 or t
        m6 = m6 xor m2
        t = t xor c4
        m2 = m6
        m6 = m6 or t
        m6 = m6 xor c0
        c0 = c0 and m2
        t = t xor c0
        m2 = m2 xor m6
        m2 = m2 xor t
        c0 = c4
        c4 = m2
        m2 = m6
        m6 = t.inv()
        t = c1
        c1 = c1 and c5
        c1 = c1 xor m7
        c5 = c5 xor m3
        c5 = c5 xor c1
        m7 = m7 or t
        m7 = m7 xor m3
        t = t xor c5
        m3 = m7
        m7 = m7 or t
        m7 = m7 xor c1
        c1 = c1 and m3
        t = t xor c1
        m3 = m3 xor m7
        m3 = m3 xor t
        c1 = c5
        c5 = m3
        m3 = m7
        m7 = t.inv()
        m0 = m0 shl 13 or (m0 ushr 32 - 13)
        c4 = c4 shl 3 or (c4 ushr 32 - 3)
        c3 = c3 xor (m0 xor c4)
        m7 = m7 xor (c4 xor (m0 shl 3))
        c3 = c3 shl 1 or (c3 ushr 32 - 1)
        m7 = m7 shl 7 or (m7 ushr 32 - 7)
        m0 = m0 xor (c3 xor m7)
        c4 = c4 xor (m7 xor (c3 shl 7))
        m0 = m0 shl 5 or (m0 ushr 32 - 5)
        c4 = c4 shl 22 or (c4 ushr 32 - 22)
        m1 = m1 shl 13 or (m1 ushr 32 - 13)
        c5 = c5 shl 3 or (c5 ushr 32 - 3)
        m2 = m2 xor (m1 xor c5)
        c6 = c6 xor (c5 xor (m1 shl 3))
        m2 = m2 shl 1 or (m2 ushr 32 - 1)
        c6 = c6 shl 7 or (c6 ushr 32 - 7)
        m1 = m1 xor (m2 xor c6)
        c5 = c5 xor (c6 xor (m2 shl 7))
        m1 = m1 shl 5 or (m1 ushr 32 - 5)
        c5 = c5 shl 22 or (c5 ushr 32 - 22)
        c0 = c0 shl 13 or (c0 ushr 32 - 13)
        m4 = m4 shl 3 or (m4 ushr 32 - 3)
        m3 = m3 xor (c0 xor m4)
        c7 = c7 xor (m4 xor (c0 shl 3))
        m3 = m3 shl 1 or (m3 ushr 32 - 1)
        c7 = c7 shl 7 or (c7 ushr 32 - 7)
        c0 = c0 xor (m3 xor c7)
        m4 = m4 xor (c7 xor (m3 shl 7))
        c0 = c0 shl 5 or (c0 ushr 32 - 5)
        m4 = m4 shl 22 or (m4 ushr 32 - 22)
        c1 = c1 shl 13 or (c1 ushr 32 - 13)
        m5 = m5 shl 3 or (m5 ushr 32 - 3)
        c2 = c2 xor (c1 xor m5)
        m6 = m6 xor (m5 xor (c1 shl 3))
        c2 = c2 shl 1 or (c2 ushr 32 - 1)
        m6 = m6 shl 7 or (m6 ushr 32 - 7)
        c1 = c1 xor (c2 xor m6)
        m5 = m5 xor (m6 xor (c2 shl 7))
        c1 = c1 shl 5 or (c1 ushr 32 - 5)
        m5 = m5 shl 22 or (m5 ushr 32 - 22)
        h[7] = h[7] xor c5
        h[6] = h[6] xor c4
        h[5] = h[5] xor m5
        h[4] = h[4] xor m4
        h[3] = h[3] xor c1
        h[2] = h[2] xor c0
        h[1] = h[1] xor m1
        h[0] = h[0] xor m0
    }

    @Suppress("LongMethod")
    private fun processFinal(b0: Int, b1: Int, b2: Int, b3: Int) {
        var rp = T256_0[b0]
        var m0 = rp[0]
        var m1 = rp[1]
        var m2 = rp[2]
        var m3 = rp[3]
        var m4 = rp[4]
        var m5 = rp[5]
        var m6 = rp[6]
        var m7 = rp[7]
        rp = T256_1[b1]
        m0 = m0 xor rp[0]
        m1 = m1 xor rp[1]
        m2 = m2 xor rp[2]
        m3 = m3 xor rp[3]
        m4 = m4 xor rp[4]
        m5 = m5 xor rp[5]
        m6 = m6 xor rp[6]
        m7 = m7 xor rp[7]
        rp = T256_2[b2]
        m0 = m0 xor rp[0]
        m1 = m1 xor rp[1]
        m2 = m2 xor rp[2]
        m3 = m3 xor rp[3]
        m4 = m4 xor rp[4]
        m5 = m5 xor rp[5]
        m6 = m6 xor rp[6]
        m7 = m7 xor rp[7]
        rp = T256_3[b3]
        m0 = m0 xor rp[0]
        m1 = m1 xor rp[1]
        m2 = m2 xor rp[2]
        m3 = m3 xor rp[3]
        m4 = m4 xor rp[4]
        m5 = m5 xor rp[5]
        m6 = m6 xor rp[6]
        m7 = m7 xor rp[7]
        var c0 = h[0]
        var c1 = h[1]
        var c2 = h[2]
        var c3 = h[3]
        var c4 = h[4]
        var c5 = h[5]
        var c6 = h[6]
        var c7 = h[7]
        var t: Int
        for (r in 0..5) {
            m0 = m0 xor ALPHA_F[0x00]
            m1 = m1 xor (ALPHA_F[0x01] xor r)
            c0 = c0 xor ALPHA_F[0x02]
            c1 = c1 xor ALPHA_F[0x03]
            c2 = c2 xor ALPHA_F[0x08]
            c3 = c3 xor ALPHA_F[0x09]
            m2 = m2 xor ALPHA_F[0x0A]
            m3 = m3 xor ALPHA_F[0x0B]
            m4 = m4 xor ALPHA_F[0x10]
            m5 = m5 xor ALPHA_F[0x11]
            c4 = c4 xor ALPHA_F[0x12]
            c5 = c5 xor ALPHA_F[0x13]
            c6 = c6 xor ALPHA_F[0x18]
            c7 = c7 xor ALPHA_F[0x19]
            m6 = m6 xor ALPHA_F[0x1A]
            m7 = m7 xor ALPHA_F[0x1B]
            t = m0
            m0 = m0 and m4
            m0 = m0 xor c6
            m4 = m4 xor c2
            m4 = m4 xor m0
            c6 = c6 or t
            c6 = c6 xor c2
            t = t xor m4
            c2 = c6
            c6 = c6 or t
            c6 = c6 xor m0
            m0 = m0 and c2
            t = t xor m0
            c2 = c2 xor c6
            c2 = c2 xor t
            m0 = m4
            m4 = c2
            c2 = c6
            c6 = t.inv()
            t = m1
            m1 = m1 and m5
            m1 = m1 xor c7
            m5 = m5 xor c3
            m5 = m5 xor m1
            c7 = c7 or t
            c7 = c7 xor c3
            t = t xor m5
            c3 = c7
            c7 = c7 or t
            c7 = c7 xor m1
            m1 = m1 and c3
            t = t xor m1
            c3 = c3 xor c7
            c3 = c3 xor t
            m1 = m5
            m5 = c3
            c3 = c7
            c7 = t.inv()
            t = c0
            c0 = c0 and c4
            c0 = c0 xor m6
            c4 = c4 xor m2
            c4 = c4 xor c0
            m6 = m6 or t
            m6 = m6 xor m2
            t = t xor c4
            m2 = m6
            m6 = m6 or t
            m6 = m6 xor c0
            c0 = c0 and m2
            t = t xor c0
            m2 = m2 xor m6
            m2 = m2 xor t
            c0 = c4
            c4 = m2
            m2 = m6
            m6 = t.inv()
            t = c1
            c1 = c1 and c5
            c1 = c1 xor m7
            c5 = c5 xor m3
            c5 = c5 xor c1
            m7 = m7 or t
            m7 = m7 xor m3
            t = t xor c5
            m3 = m7
            m7 = m7 or t
            m7 = m7 xor c1
            c1 = c1 and m3
            t = t xor c1
            m3 = m3 xor m7
            m3 = m3 xor t
            c1 = c5
            c5 = m3
            m3 = m7
            m7 = t.inv()
            m0 = m0 shl 13 or (m0 ushr 32 - 13)
            c4 = c4 shl 3 or (c4 ushr 32 - 3)
            c3 = c3 xor (m0 xor c4)
            m7 = m7 xor (c4 xor (m0 shl 3))
            c3 = c3 shl 1 or (c3 ushr 32 - 1)
            m7 = m7 shl 7 or (m7 ushr 32 - 7)
            m0 = m0 xor (c3 xor m7)
            c4 = c4 xor (m7 xor (c3 shl 7))
            m0 = m0 shl 5 or (m0 ushr 32 - 5)
            c4 = c4 shl 22 or (c4 ushr 32 - 22)
            m1 = m1 shl 13 or (m1 ushr 32 - 13)
            c5 = c5 shl 3 or (c5 ushr 32 - 3)
            m2 = m2 xor (m1 xor c5)
            c6 = c6 xor (c5 xor (m1 shl 3))
            m2 = m2 shl 1 or (m2 ushr 32 - 1)
            c6 = c6 shl 7 or (c6 ushr 32 - 7)
            m1 = m1 xor (m2 xor c6)
            c5 = c5 xor (c6 xor (m2 shl 7))
            m1 = m1 shl 5 or (m1 ushr 32 - 5)
            c5 = c5 shl 22 or (c5 ushr 32 - 22)
            c0 = c0 shl 13 or (c0 ushr 32 - 13)
            m4 = m4 shl 3 or (m4 ushr 32 - 3)
            m3 = m3 xor (c0 xor m4)
            c7 = c7 xor (m4 xor (c0 shl 3))
            m3 = m3 shl 1 or (m3 ushr 32 - 1)
            c7 = c7 shl 7 or (c7 ushr 32 - 7)
            c0 = c0 xor (m3 xor c7)
            m4 = m4 xor (c7 xor (m3 shl 7))
            c0 = c0 shl 5 or (c0 ushr 32 - 5)
            m4 = m4 shl 22 or (m4 ushr 32 - 22)
            c1 = c1 shl 13 or (c1 ushr 32 - 13)
            m5 = m5 shl 3 or (m5 ushr 32 - 3)
            c2 = c2 xor (c1 xor m5)
            m6 = m6 xor (m5 xor (c1 shl 3))
            c2 = c2 shl 1 or (c2 ushr 32 - 1)
            m6 = m6 shl 7 or (m6 ushr 32 - 7)
            c1 = c1 xor (c2 xor m6)
            m5 = m5 xor (m6 xor (c2 shl 7))
            c1 = c1 shl 5 or (c1 ushr 32 - 5)
            m5 = m5 shl 22 or (m5 ushr 32 - 22)
        }
        h[7] = h[7] xor c5
        h[6] = h[6] xor c4
        h[5] = h[5] xor m5
        h[4] = h[4] xor m4
        h[3] = h[3] xor c1
        h[2] = h[2] xor c0
        h[1] = h[1] xor m1
        h[0] = h[0] xor m0
    }

    override fun toString(): String {
        return "Hamsi-" + (digestLength shl 3)
    }

    companion object {
        private val Tsrc = arrayOf(
            intArrayOf(
                0x045f0000, -0x63b56c37, 0x62fc79d0, 0x731ebdc2,
                -0x1fd88000, 0x19dce008, -0x28f8a27e, 0x5ad2e31d
            ), intArrayOf(
                -0x1b878000, -0x7a698c3f, -0x4a04dbae, 0x29cc5edf,
                0x045f0000, -0x63b56c37, 0x62fc79d0, 0x731ebdc2
            ), intArrayOf(
                -0x19a90000, 0x4bb33a25, -0x7b7a6746, 0x1041003e,
                -0xbb3c000, 0x10a4e3cd, 0x097f5711, -0x218833b4
            ), intArrayOf(
                0x121b4000, 0x5b17d9e8, -0x72053055, -0x31c9338e,
                -0x19a90000, 0x4bb33a25, -0x7b7a6746, 0x1041003e
            ), intArrayOf(
                -0x68ad0000, 0x204f6ed3, 0x77b9e80f, -0x5e13a13f,
                0x7e792000, -0x6be71dd1, 0x6643d258, -0x63daa41b
            ), intArrayOf(
                -0x16d5e000, -0x4ba87304, 0x11fa3a57, 0x3dc90524,
                -0x68ad0000, 0x204f6ed3, 0x77b9e80f, -0x5e13a13f
            ), intArrayOf(
                -0x34570000, -0x6fd8c897, -0x44230bf9, -0x2f0b509f,
                -0x40c3f000, -0x35f38ee9, 0x3321e92c, -0x31edd20d
            ), intArrayOf(
                0x74951000, 0x5a2b467e, -0x7702e2d5, 0x1ee68292,
                -0x34570000, -0x6fd8c897, -0x44230bf9, -0x2f0b509f
            ), intArrayOf(
                -0x1e750000, 0x5459887d, -0x40ed7c2d, 0x1b666a73,
                0x3fb90800, 0x7cdad883, -0x316856ec, -0x42260a1b
            ), intArrayOf(
                -0x21cdf800, 0x288350fe, 0x71852ac7, -0x5940606a,
                -0x1e750000, 0x5459887d, -0x40ed7c2d, 0x1b666a73
            ), intArrayOf(
                0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6,
                -0x647cfc00, 0x2227ff88, 0x05b7ad5a, -0x520d38d0
            ), intArrayOf(
                -0x70c1fc00, 0x0d9dc877, 0x6fc548e1, -0x7672d32a,
                0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6
            ), intArrayOf(
                -0x11da0000, 0x124b683e, -0x7f3d2971, 0x3bf3ab2c,
                0x499e0200, 0x0d59ec0d, -0x1fd8d083, -0x5a1821a6
            ), intArrayOf(
                -0x5847fe00, 0x1f128433, 0x60e5f9f2, -0x61eb8a8a,
                -0x11da0000, 0x124b683e, -0x7f3d2971, 0x3bf3ab2c
            ), intArrayOf(
                0x734c0000, -0x6a90582a, -0x5d62ed69, 0x6ee56854,
                -0x3b17ff00, 0x1f70960e, 0x2714ca3c, -0x77def3d0
            ), intArrayOf(
                -0x485bff00, -0x75e0ce28, -0x7a762755, -0x193b9b9c,
                0x734c0000, -0x6a90582a, -0x5d62ed69, 0x6ee56854
            ), intArrayOf(
                0x39a60000, 0x4ab753eb, -0x2eb1f6b5, -0x488d4bd5,
                0x62740080, 0x0fb84b07, 0x138a651e, 0x44100618
            ), intArrayOf(
                0x5bd20080, 0x450f18ec, -0x3d3b93ab, -0xc9d4dcd,
                0x39a60000, 0x4ab753eb, -0x2eb1f6b5, -0x488d4bd5
            ), intArrayOf(
                0x78ab0000, -0x5f32a5cc, 0x5d5ca0f7, 0x727784cb,
                0x35650040, -0x646949b6, 0x6b39cb5f, 0x5114bece
            ), intArrayOf(
                0x4dce0040, 0x3b5bec7e, 0x36656ba8, 0x23633a05,
                0x78ab0000, -0x5f32a5cc, 0x5d5ca0f7, 0x727784cb
            ), intArrayOf(
                0x5c720000, -0x364532ee, 0x79a90df9, 0x63e92178,
                -0x135ffe0, 0x485d28e4, -0x7f98be03, -0x7eb97e48
            ), intArrayOf(
                -0x5d47ffe0, -0x7e181a0a, -0x631b3fc, -0x1d505f40,
                0x5c720000, -0x364532ee, 0x79a90df9, 0x63e92178
            ), intArrayOf(
                0x2e390000, 0x64dd6689, 0x3cd406fc, -0x4e0b6f44,
                0x7f650010, 0x242e1472, -0x3fccdf02, -0x3f5c3f23
            ), intArrayOf(
                0x515c0010, 0x40f372fb, -0x318d9fe, 0x71575061,
                0x2e390000, 0x64dd6689, 0x3cd406fc, -0x4e0b6f44
            ), intArrayOf(
                0x171c0000, -0x4d91ccbc, -0x61957c82, 0x58f8485f,
                -0x404dfff8, -0x6de8f5c7, 0x6019107f, -0x1fae9f92
            ), intArrayOf(
                -0x5751fff8, 0x2079397d, -0x18c6cff, -0x4756d7cf,
                0x171c0000, -0x4d91ccbc, -0x61957c82, 0x58f8485f
            ), intArrayOf(
                0x6ba90000, 0x40ebf9aa, -0x67cde3c3, 0x76acc733,
                -0x445efffc, -0x33628923, 0x05f7ac6d, -0x26191117
            ), intArrayOf(
                -0x2ff7fffc, -0x73897089, -0x623a4fb0, -0x50b5d626,
                0x6ba90000, 0x40ebf9aa, -0x67cde3c3, 0x76acc733
            ), intArrayOf(
                0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46,
                -0x2670fffe, 0x7a04a8a7, -0x1ff8501a, -0x6012b549
            ), intArrayOf(
                -0x77dcfffe, 0x5fe7a7b3, -0x661a7a56, -0x728a080f,
                0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46
            ), intArrayOf(
                -0x370f0000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf,
                0x08bf0001, 0x38942792, -0x3a070c5f, -0x19c7847c
            ), intArrayOf(
                -0x3fb1ffff, 0x33b9c010, -0x51f144fb, -0x4a5b39c5,
                -0x370f0000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf
            )
        )

        @Suppress("NestedBlockDepth")
        private fun makeT(x: Int): Array<IntArray> {
            val t = Array(256) { IntArray(8) }
            for (y in 0..255) {
                for (z in 0..7) {
                    var a = 0
                    for (k in 0..7) {
                        if (y and (1 shl 7 - k) != 0) a = a xor Tsrc[x + k][z]
                    }
                    t[y][z] = a
                }
            }
            return t
        }

        private val T256_0 = makeT(0)
        private val T256_1 = makeT(8)
        private val T256_2 = makeT(16)
        private val T256_3 = makeT(24)
        private val ALPHA_N = intArrayOf(
            -0xff0f10, -0x33335556, -0xf0f3334, -0xff5556,
            -0x33335556, -0xf0f0100, -0x55553334, -0xf0f0100,
            -0xf0f3334, -0x55550100, -0x33330100, -0x55550f10,
            -0x55550f10, -0xff3334, -0x33330f10, -0xff5556,
            -0x33335556, -0xff0f10, -0xff5556, -0xf0f3334,
            -0xf0f0100, -0x33335556, -0xf0f0100, -0x55553334,
            -0x55550100, -0xf0f3334, -0x55550f10, -0x33330100,
            -0xff3334, -0x55550f10, -0xff5556, -0x33330f10
        )
        private val ALPHA_F = intArrayOf(
            -0x35069c64, 0x0ff0f9c0, 0x639c0ff0, -0x35060640,
            0x0ff0f9c0, 0x639ccaf9, -0x63ff010, 0x639ccaf9,
            0x639c0ff0, -0x63f3507, 0x0ff0caf9, -0x63f9c64,
            -0x63f9c64, -0x3506f010, 0x0ff0639c, -0x35060640,
            0x0ff0f9c0, -0x35069c64, -0x35060640, 0x639c0ff0,
            0x639ccaf9, 0x0ff0f9c0, 0x639ccaf9, -0x63ff010,
            -0x63f3507, 0x639c0ff0, -0x63f9c64, 0x0ff0caf9,
            -0x3506f010, -0x63f9c64, -0x35060640, 0x0ff0639c
        )
    }
}
