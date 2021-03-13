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
 * This class implements Hamsi-384 and Hamsi-512.
 *
 * @version $Revision: 239 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("TooManyFunctions", "MagicNumber", "LargeClass")
internal abstract class HamsiBigCore<D : HamsiBigCore<D>> : Digest<D> {
    private val h: IntArray = IntArray(16)
    private var bitCount: Long = 0
    private var partial: Long = 0
    private var partialLen = 0

    init {
        reset()
    }

    override fun update(input: Byte) {
        bitCount += 8
        partial = partial shl 8 or (input.toLong() and 0xFF)
        partialLen++
        if (partialLen == 8) {
            process(
                (partial ushr 56).toInt() and 0xFF,
                (partial ushr 48).toInt() and 0xFF,
                (partial ushr 40).toInt() and 0xFF,
                (partial ushr 32).toInt() and 0xFF,
                partial.toInt() ushr 24 and 0xFF,
                partial.toInt() ushr 16 and 0xFF,
                partial.toInt() ushr 8 and 0xFF,
                partial.toInt() and 0xFF
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
            while (partialLen < 8 && len > 0) {
                partial = (partial shl 8
                        or (input[off++].toLong() and 0xFF))
                partialLen++
                len--
            }
            if (partialLen < 8) return
            process(
                (partial ushr 56).toInt() and 0xFF,
                (partial ushr 48).toInt() and 0xFF,
                (partial ushr 40).toInt() and 0xFF,
                (partial ushr 32).toInt() and 0xFF,
                partial.toInt() ushr 24 and 0xFF,
                partial.toInt() ushr 16 and 0xFF,
                partial.toInt() ushr 8 and 0xFF,
                partial.toInt() and 0xFF
            )
            partialLen = 0
        }
        while (len >= 8) {
            process(
                input[off + 0].toInt() and 0xFF,
                input[off + 1].toInt() and 0xFF,
                input[off + 2].toInt() and 0xFF,
                input[off + 3].toInt() and 0xFF,
                input[off + 4].toInt() and 0xFF,
                input[off + 5].toInt() and 0xFF,
                input[off + 6].toInt() and 0xFF,
                input[off + 7].toInt() and 0xFF
            )
            off += 8
            len -= 8
        }
        partialLen = len
        while (len-- > 0) partial = partial shl 8 or (input[off++].toLong() and 0xFF)
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
        processFinal(
            (bitCount ushr 56).toInt() and 0xFF,
            (bitCount ushr 48).toInt() and 0xFF,
            (bitCount ushr 40).toInt() and 0xFF,
            (bitCount ushr 32).toInt() and 0xFF,
            bitCount.toInt() ushr 24 and 0xFF,
            bitCount.toInt() ushr 16 and 0xFF,
            bitCount.toInt() ushr 8 and 0xFF,
            bitCount.toInt() and 0xFF
        )
        val n = digestLength
        if (len > n) len = n
        var ch = 0
        val hoff = if (n == 48) HOFF384 else HOFF512
        var i = 0
        var j = 0
        while (i < len) {
            if (i and 3 == 0) ch = h[hoff[j++]]
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

    @Suppress("LongParameterList", "LongMethod")
    private fun process(b0: Int, b1: Int, b2: Int, b3: Int, b4: Int, b5: Int, b6: Int, b7: Int) {
        var rp = T512_0[b0]
        var m0 = rp[0x0]
        var m1 = rp[0x1]
        var m2 = rp[0x2]
        var m3 = rp[0x3]
        var m4 = rp[0x4]
        var m5 = rp[0x5]
        var m6 = rp[0x6]
        var m7 = rp[0x7]
        var m8 = rp[0x8]
        var m9 = rp[0x9]
        var mA = rp[0xA]
        var mB = rp[0xB]
        var mC = rp[0xC]
        var mD = rp[0xD]
        var mE = rp[0xE]
        var mF = rp[0xF]
        rp = T512_1[b1]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_2[b2]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_3[b3]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_4[b4]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_5[b5]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_6[b6]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_7[b7]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        var c0 = h[0x0]
        var c1 = h[0x1]
        var c2 = h[0x2]
        var c3 = h[0x3]
        var c4 = h[0x4]
        var c5 = h[0x5]
        var c6 = h[0x6]
        var c7 = h[0x7]
        var c8 = h[0x8]
        var c9 = h[0x9]
        var cA = h[0xA]
        var cB = h[0xB]
        var cC = h[0xC]
        var cD = h[0xD]
        var cE = h[0xE]
        var cF = h[0xF]
        var t: Int
        for (r in 0..5) {
            m0 = m0 xor ALPHA_N[0x00]
            m1 = m1 xor (ALPHA_N[0x01] xor r)
            c0 = c0 xor ALPHA_N[0x02]
            c1 = c1 xor ALPHA_N[0x03]
            m2 = m2 xor ALPHA_N[0x04]
            m3 = m3 xor ALPHA_N[0x05]
            c2 = c2 xor ALPHA_N[0x06]
            c3 = c3 xor ALPHA_N[0x07]
            c4 = c4 xor ALPHA_N[0x08]
            c5 = c5 xor ALPHA_N[0x09]
            m4 = m4 xor ALPHA_N[0x0A]
            m5 = m5 xor ALPHA_N[0x0B]
            c6 = c6 xor ALPHA_N[0x0C]
            c7 = c7 xor ALPHA_N[0x0D]
            m6 = m6 xor ALPHA_N[0x0E]
            m7 = m7 xor ALPHA_N[0x0F]
            m8 = m8 xor ALPHA_N[0x10]
            m9 = m9 xor ALPHA_N[0x11]
            c8 = c8 xor ALPHA_N[0x12]
            c9 = c9 xor ALPHA_N[0x13]
            mA = mA xor ALPHA_N[0x14]
            mB = mB xor ALPHA_N[0x15]
            cA = cA xor ALPHA_N[0x16]
            cB = cB xor ALPHA_N[0x17]
            cC = cC xor ALPHA_N[0x18]
            cD = cD xor ALPHA_N[0x19]
            mC = mC xor ALPHA_N[0x1A]
            mD = mD xor ALPHA_N[0x1B]
            cE = cE xor ALPHA_N[0x1C]
            cF = cF xor ALPHA_N[0x1D]
            mE = mE xor ALPHA_N[0x1E]
            mF = mF xor ALPHA_N[0x1F]
            t = m0
            m0 = m0 and m8
            m0 = m0 xor cC
            m8 = m8 xor c4
            m8 = m8 xor m0
            cC = cC or t
            cC = cC xor c4
            t = t xor m8
            c4 = cC
            cC = cC or t
            cC = cC xor m0
            m0 = m0 and c4
            t = t xor m0
            c4 = c4 xor cC
            c4 = c4 xor t
            m0 = m8
            m8 = c4
            c4 = cC
            cC = t.inv()
            t = m1
            m1 = m1 and m9
            m1 = m1 xor cD
            m9 = m9 xor c5
            m9 = m9 xor m1
            cD = cD or t
            cD = cD xor c5
            t = t xor m9
            c5 = cD
            cD = cD or t
            cD = cD xor m1
            m1 = m1 and c5
            t = t xor m1
            c5 = c5 xor cD
            c5 = c5 xor t
            m1 = m9
            m9 = c5
            c5 = cD
            cD = t.inv()
            t = c0
            c0 = c0 and c8
            c0 = c0 xor mC
            c8 = c8 xor m4
            c8 = c8 xor c0
            mC = mC or t
            mC = mC xor m4
            t = t xor c8
            m4 = mC
            mC = mC or t
            mC = mC xor c0
            c0 = c0 and m4
            t = t xor c0
            m4 = m4 xor mC
            m4 = m4 xor t
            c0 = c8
            c8 = m4
            m4 = mC
            mC = t.inv()
            t = c1
            c1 = c1 and c9
            c1 = c1 xor mD
            c9 = c9 xor m5
            c9 = c9 xor c1
            mD = mD or t
            mD = mD xor m5
            t = t xor c9
            m5 = mD
            mD = mD or t
            mD = mD xor c1
            c1 = c1 and m5
            t = t xor c1
            m5 = m5 xor mD
            m5 = m5 xor t
            c1 = c9
            c9 = m5
            m5 = mD
            mD = t.inv()
            t = m2
            m2 = m2 and mA
            m2 = m2 xor cE
            mA = mA xor c6
            mA = mA xor m2
            cE = cE or t
            cE = cE xor c6
            t = t xor mA
            c6 = cE
            cE = cE or t
            cE = cE xor m2
            m2 = m2 and c6
            t = t xor m2
            c6 = c6 xor cE
            c6 = c6 xor t
            m2 = mA
            mA = c6
            c6 = cE
            cE = t.inv()
            t = m3
            m3 = m3 and mB
            m3 = m3 xor cF
            mB = mB xor c7
            mB = mB xor m3
            cF = cF or t
            cF = cF xor c7
            t = t xor mB
            c7 = cF
            cF = cF or t
            cF = cF xor m3
            m3 = m3 and c7
            t = t xor m3
            c7 = c7 xor cF
            c7 = c7 xor t
            m3 = mB
            mB = c7
            c7 = cF
            cF = t.inv()
            t = c2
            c2 = c2 and cA
            c2 = c2 xor mE
            cA = cA xor m6
            cA = cA xor c2
            mE = mE or t
            mE = mE xor m6
            t = t xor cA
            m6 = mE
            mE = mE or t
            mE = mE xor c2
            c2 = c2 and m6
            t = t xor c2
            m6 = m6 xor mE
            m6 = m6 xor t
            c2 = cA
            cA = m6
            m6 = mE
            mE = t.inv()
            t = c3
            c3 = c3 and cB
            c3 = c3 xor mF
            cB = cB xor m7
            cB = cB xor c3
            mF = mF or t
            mF = mF xor m7
            t = t xor cB
            m7 = mF
            mF = mF or t
            mF = mF xor c3
            c3 = c3 and m7
            t = t xor c3
            m7 = m7 xor mF
            m7 = m7 xor t
            c3 = cB
            cB = m7
            m7 = mF
            mF = t.inv()
            m0 = m0 shl 13 or (m0 ushr 32 - 13)
            c8 = c8 shl 3 or (c8 ushr 32 - 3)
            c5 = c5 xor (m0 xor c8)
            mD = mD xor (c8 xor (m0 shl 3))
            c5 = c5 shl 1 or (c5 ushr 32 - 1)
            mD = mD shl 7 or (mD ushr 32 - 7)
            m0 = m0 xor (c5 xor mD)
            c8 = c8 xor (mD xor (c5 shl 7))
            m0 = m0 shl 5 or (m0 ushr 32 - 5)
            c8 = c8 shl 22 or (c8 ushr 32 - 22)
            m1 = m1 shl 13 or (m1 ushr 32 - 13)
            c9 = c9 shl 3 or (c9 ushr 32 - 3)
            m4 = m4 xor (m1 xor c9)
            cE = cE xor (c9 xor (m1 shl 3))
            m4 = m4 shl 1 or (m4 ushr 32 - 1)
            cE = cE shl 7 or (cE ushr 32 - 7)
            m1 = m1 xor (m4 xor cE)
            c9 = c9 xor (cE xor (m4 shl 7))
            m1 = m1 shl 5 or (m1 ushr 32 - 5)
            c9 = c9 shl 22 or (c9 ushr 32 - 22)
            c0 = c0 shl 13 or (c0 ushr 32 - 13)
            mA = mA shl 3 or (mA ushr 32 - 3)
            m5 = m5 xor (c0 xor mA)
            cF = cF xor (mA xor (c0 shl 3))
            m5 = m5 shl 1 or (m5 ushr 32 - 1)
            cF = cF shl 7 or (cF ushr 32 - 7)
            c0 = c0 xor (m5 xor cF)
            mA = mA xor (cF xor (m5 shl 7))
            c0 = c0 shl 5 or (c0 ushr 32 - 5)
            mA = mA shl 22 or (mA ushr 32 - 22)
            c1 = c1 shl 13 or (c1 ushr 32 - 13)
            mB = mB shl 3 or (mB ushr 32 - 3)
            c6 = c6 xor (c1 xor mB)
            mE = mE xor (mB xor (c1 shl 3))
            c6 = c6 shl 1 or (c6 ushr 32 - 1)
            mE = mE shl 7 or (mE ushr 32 - 7)
            c1 = c1 xor (c6 xor mE)
            mB = mB xor (mE xor (c6 shl 7))
            c1 = c1 shl 5 or (c1 ushr 32 - 5)
            mB = mB shl 22 or (mB ushr 32 - 22)
            m2 = m2 shl 13 or (m2 ushr 32 - 13)
            cA = cA shl 3 or (cA ushr 32 - 3)
            c7 = c7 xor (m2 xor cA)
            mF = mF xor (cA xor (m2 shl 3))
            c7 = c7 shl 1 or (c7 ushr 32 - 1)
            mF = mF shl 7 or (mF ushr 32 - 7)
            m2 = m2 xor (c7 xor mF)
            cA = cA xor (mF xor (c7 shl 7))
            m2 = m2 shl 5 or (m2 ushr 32 - 5)
            cA = cA shl 22 or (cA ushr 32 - 22)
            m3 = m3 shl 13 or (m3 ushr 32 - 13)
            cB = cB shl 3 or (cB ushr 32 - 3)
            m6 = m6 xor (m3 xor cB)
            cC = cC xor (cB xor (m3 shl 3))
            m6 = m6 shl 1 or (m6 ushr 32 - 1)
            cC = cC shl 7 or (cC ushr 32 - 7)
            m3 = m3 xor (m6 xor cC)
            cB = cB xor (cC xor (m6 shl 7))
            m3 = m3 shl 5 or (m3 ushr 32 - 5)
            cB = cB shl 22 or (cB ushr 32 - 22)
            c2 = c2 shl 13 or (c2 ushr 32 - 13)
            m8 = m8 shl 3 or (m8 ushr 32 - 3)
            m7 = m7 xor (c2 xor m8)
            cD = cD xor (m8 xor (c2 shl 3))
            m7 = m7 shl 1 or (m7 ushr 32 - 1)
            cD = cD shl 7 or (cD ushr 32 - 7)
            c2 = c2 xor (m7 xor cD)
            m8 = m8 xor (cD xor (m7 shl 7))
            c2 = c2 shl 5 or (c2 ushr 32 - 5)
            m8 = m8 shl 22 or (m8 ushr 32 - 22)
            c3 = c3 shl 13 or (c3 ushr 32 - 13)
            m9 = m9 shl 3 or (m9 ushr 32 - 3)
            c4 = c4 xor (c3 xor m9)
            mC = mC xor (m9 xor (c3 shl 3))
            c4 = c4 shl 1 or (c4 ushr 32 - 1)
            mC = mC shl 7 or (mC ushr 32 - 7)
            c3 = c3 xor (c4 xor mC)
            m9 = m9 xor (mC xor (c4 shl 7))
            c3 = c3 shl 5 or (c3 ushr 32 - 5)
            m9 = m9 shl 22 or (m9 ushr 32 - 22)
            m0 = m0 shl 13 or (m0 ushr 32 - 13)
            m3 = m3 shl 3 or (m3 ushr 32 - 3)
            c0 = c0 xor (m0 xor m3)
            c3 = c3 xor (m3 xor (m0 shl 3))
            c0 = c0 shl 1 or (c0 ushr 32 - 1)
            c3 = c3 shl 7 or (c3 ushr 32 - 7)
            m0 = m0 xor (c0 xor c3)
            m3 = m3 xor (c3 xor (c0 shl 7))
            m0 = m0 shl 5 or (m0 ushr 32 - 5)
            m3 = m3 shl 22 or (m3 ushr 32 - 22)
            m8 = m8 shl 13 or (m8 ushr 32 - 13)
            mB = mB shl 3 or (mB ushr 32 - 3)
            c9 = c9 xor (m8 xor mB)
            cA = cA xor (mB xor (m8 shl 3))
            c9 = c9 shl 1 or (c9 ushr 32 - 1)
            cA = cA shl 7 or (cA ushr 32 - 7)
            m8 = m8 xor (c9 xor cA)
            mB = mB xor (cA xor (c9 shl 7))
            m8 = m8 shl 5 or (m8 ushr 32 - 5)
            mB = mB shl 22 or (mB ushr 32 - 22)
            c5 = c5 shl 13 or (c5 ushr 32 - 13)
            c6 = c6 shl 3 or (c6 ushr 32 - 3)
            m5 = m5 xor (c5 xor c6)
            m6 = m6 xor (c6 xor (c5 shl 3))
            m5 = m5 shl 1 or (m5 ushr 32 - 1)
            m6 = m6 shl 7 or (m6 ushr 32 - 7)
            c5 = c5 xor (m5 xor m6)
            c6 = c6 xor (m6 xor (m5 shl 7))
            c5 = c5 shl 5 or (c5 ushr 32 - 5)
            c6 = c6 shl 22 or (c6 ushr 32 - 22)
            cD = cD shl 13 or (cD ushr 32 - 13)
            cE = cE shl 3 or (cE ushr 32 - 3)
            mC = mC xor (cD xor cE)
            mF = mF xor (cE xor (cD shl 3))
            mC = mC shl 1 or (mC ushr 32 - 1)
            mF = mF shl 7 or (mF ushr 32 - 7)
            cD = cD xor (mC xor mF)
            cE = cE xor (mF xor (mC shl 7))
            cD = cD shl 5 or (cD ushr 32 - 5)
            cE = cE shl 22 or (cE ushr 32 - 22)
        }
        h[0xF] = h[0xF] xor cB
        h[0xE] = h[0xE] xor cA
        h[0xD] = h[0xD] xor mB
        h[0xC] = h[0xC] xor mA
        h[0xB] = h[0xB] xor c9
        h[0xA] = h[0xA] xor c8
        h[0x9] = h[0x9] xor m9
        h[0x8] = h[0x8] xor m8
        h[0x7] = h[0x7] xor c3
        h[0x6] = h[0x6] xor c2
        h[0x5] = h[0x5] xor m3
        h[0x4] = h[0x4] xor m2
        h[0x3] = h[0x3] xor c1
        h[0x2] = h[0x2] xor c0
        h[0x1] = h[0x1] xor m1
        h[0x0] = h[0x0] xor m0
    }

    @Suppress("LongParameterList", "LongMethod")
    private fun processFinal(b0: Int, b1: Int, b2: Int, b3: Int, b4: Int, b5: Int, b6: Int, b7: Int) {
        var rp = T512_0[b0]
        var m0 = rp[0x0]
        var m1 = rp[0x1]
        var m2 = rp[0x2]
        var m3 = rp[0x3]
        var m4 = rp[0x4]
        var m5 = rp[0x5]
        var m6 = rp[0x6]
        var m7 = rp[0x7]
        var m8 = rp[0x8]
        var m9 = rp[0x9]
        var mA = rp[0xA]
        var mB = rp[0xB]
        var mC = rp[0xC]
        var mD = rp[0xD]
        var mE = rp[0xE]
        var mF = rp[0xF]
        rp = T512_1[b1]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_2[b2]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_3[b3]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_4[b4]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_5[b5]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_6[b6]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        rp = T512_7[b7]
        m0 = m0 xor rp[0x0]
        m1 = m1 xor rp[0x1]
        m2 = m2 xor rp[0x2]
        m3 = m3 xor rp[0x3]
        m4 = m4 xor rp[0x4]
        m5 = m5 xor rp[0x5]
        m6 = m6 xor rp[0x6]
        m7 = m7 xor rp[0x7]
        m8 = m8 xor rp[0x8]
        m9 = m9 xor rp[0x9]
        mA = mA xor rp[0xA]
        mB = mB xor rp[0xB]
        mC = mC xor rp[0xC]
        mD = mD xor rp[0xD]
        mE = mE xor rp[0xE]
        mF = mF xor rp[0xF]
        var c0 = h[0x0]
        var c1 = h[0x1]
        var c2 = h[0x2]
        var c3 = h[0x3]
        var c4 = h[0x4]
        var c5 = h[0x5]
        var c6 = h[0x6]
        var c7 = h[0x7]
        var c8 = h[0x8]
        var c9 = h[0x9]
        var cA = h[0xA]
        var cB = h[0xB]
        var cC = h[0xC]
        var cD = h[0xD]
        var cE = h[0xE]
        var cF = h[0xF]
        var t: Int
        for (r in 0..11) {
            m0 = m0 xor ALPHA_F[0x00]
            m1 = m1 xor (ALPHA_F[0x01] xor r)
            c0 = c0 xor ALPHA_F[0x02]
            c1 = c1 xor ALPHA_F[0x03]
            m2 = m2 xor ALPHA_F[0x04]
            m3 = m3 xor ALPHA_F[0x05]
            c2 = c2 xor ALPHA_F[0x06]
            c3 = c3 xor ALPHA_F[0x07]
            c4 = c4 xor ALPHA_F[0x08]
            c5 = c5 xor ALPHA_F[0x09]
            m4 = m4 xor ALPHA_F[0x0A]
            m5 = m5 xor ALPHA_F[0x0B]
            c6 = c6 xor ALPHA_F[0x0C]
            c7 = c7 xor ALPHA_F[0x0D]
            m6 = m6 xor ALPHA_F[0x0E]
            m7 = m7 xor ALPHA_F[0x0F]
            m8 = m8 xor ALPHA_F[0x10]
            m9 = m9 xor ALPHA_F[0x11]
            c8 = c8 xor ALPHA_F[0x12]
            c9 = c9 xor ALPHA_F[0x13]
            mA = mA xor ALPHA_F[0x14]
            mB = mB xor ALPHA_F[0x15]
            cA = cA xor ALPHA_F[0x16]
            cB = cB xor ALPHA_F[0x17]
            cC = cC xor ALPHA_F[0x18]
            cD = cD xor ALPHA_F[0x19]
            mC = mC xor ALPHA_F[0x1A]
            mD = mD xor ALPHA_F[0x1B]
            cE = cE xor ALPHA_F[0x1C]
            cF = cF xor ALPHA_F[0x1D]
            mE = mE xor ALPHA_F[0x1E]
            mF = mF xor ALPHA_F[0x1F]
            t = m0
            m0 = m0 and m8
            m0 = m0 xor cC
            m8 = m8 xor c4
            m8 = m8 xor m0
            cC = cC or t
            cC = cC xor c4
            t = t xor m8
            c4 = cC
            cC = cC or t
            cC = cC xor m0
            m0 = m0 and c4
            t = t xor m0
            c4 = c4 xor cC
            c4 = c4 xor t
            m0 = m8
            m8 = c4
            c4 = cC
            cC = t.inv()
            t = m1
            m1 = m1 and m9
            m1 = m1 xor cD
            m9 = m9 xor c5
            m9 = m9 xor m1
            cD = cD or t
            cD = cD xor c5
            t = t xor m9
            c5 = cD
            cD = cD or t
            cD = cD xor m1
            m1 = m1 and c5
            t = t xor m1
            c5 = c5 xor cD
            c5 = c5 xor t
            m1 = m9
            m9 = c5
            c5 = cD
            cD = t.inv()
            t = c0
            c0 = c0 and c8
            c0 = c0 xor mC
            c8 = c8 xor m4
            c8 = c8 xor c0
            mC = mC or t
            mC = mC xor m4
            t = t xor c8
            m4 = mC
            mC = mC or t
            mC = mC xor c0
            c0 = c0 and m4
            t = t xor c0
            m4 = m4 xor mC
            m4 = m4 xor t
            c0 = c8
            c8 = m4
            m4 = mC
            mC = t.inv()
            t = c1
            c1 = c1 and c9
            c1 = c1 xor mD
            c9 = c9 xor m5
            c9 = c9 xor c1
            mD = mD or t
            mD = mD xor m5
            t = t xor c9
            m5 = mD
            mD = mD or t
            mD = mD xor c1
            c1 = c1 and m5
            t = t xor c1
            m5 = m5 xor mD
            m5 = m5 xor t
            c1 = c9
            c9 = m5
            m5 = mD
            mD = t.inv()
            t = m2
            m2 = m2 and mA
            m2 = m2 xor cE
            mA = mA xor c6
            mA = mA xor m2
            cE = cE or t
            cE = cE xor c6
            t = t xor mA
            c6 = cE
            cE = cE or t
            cE = cE xor m2
            m2 = m2 and c6
            t = t xor m2
            c6 = c6 xor cE
            c6 = c6 xor t
            m2 = mA
            mA = c6
            c6 = cE
            cE = t.inv()
            t = m3
            m3 = m3 and mB
            m3 = m3 xor cF
            mB = mB xor c7
            mB = mB xor m3
            cF = cF or t
            cF = cF xor c7
            t = t xor mB
            c7 = cF
            cF = cF or t
            cF = cF xor m3
            m3 = m3 and c7
            t = t xor m3
            c7 = c7 xor cF
            c7 = c7 xor t
            m3 = mB
            mB = c7
            c7 = cF
            cF = t.inv()
            t = c2
            c2 = c2 and cA
            c2 = c2 xor mE
            cA = cA xor m6
            cA = cA xor c2
            mE = mE or t
            mE = mE xor m6
            t = t xor cA
            m6 = mE
            mE = mE or t
            mE = mE xor c2
            c2 = c2 and m6
            t = t xor c2
            m6 = m6 xor mE
            m6 = m6 xor t
            c2 = cA
            cA = m6
            m6 = mE
            mE = t.inv()
            t = c3
            c3 = c3 and cB
            c3 = c3 xor mF
            cB = cB xor m7
            cB = cB xor c3
            mF = mF or t
            mF = mF xor m7
            t = t xor cB
            m7 = mF
            mF = mF or t
            mF = mF xor c3
            c3 = c3 and m7
            t = t xor c3
            m7 = m7 xor mF
            m7 = m7 xor t
            c3 = cB
            cB = m7
            m7 = mF
            mF = t.inv()
            m0 = m0 shl 13 or (m0 ushr 32 - 13)
            c8 = c8 shl 3 or (c8 ushr 32 - 3)
            c5 = c5 xor (m0 xor c8)
            mD = mD xor (c8 xor (m0 shl 3))
            c5 = c5 shl 1 or (c5 ushr 32 - 1)
            mD = mD shl 7 or (mD ushr 32 - 7)
            m0 = m0 xor (c5 xor mD)
            c8 = c8 xor (mD xor (c5 shl 7))
            m0 = m0 shl 5 or (m0 ushr 32 - 5)
            c8 = c8 shl 22 or (c8 ushr 32 - 22)
            m1 = m1 shl 13 or (m1 ushr 32 - 13)
            c9 = c9 shl 3 or (c9 ushr 32 - 3)
            m4 = m4 xor (m1 xor c9)
            cE = cE xor (c9 xor (m1 shl 3))
            m4 = m4 shl 1 or (m4 ushr 32 - 1)
            cE = cE shl 7 or (cE ushr 32 - 7)
            m1 = m1 xor (m4 xor cE)
            c9 = c9 xor (cE xor (m4 shl 7))
            m1 = m1 shl 5 or (m1 ushr 32 - 5)
            c9 = c9 shl 22 or (c9 ushr 32 - 22)
            c0 = c0 shl 13 or (c0 ushr 32 - 13)
            mA = mA shl 3 or (mA ushr 32 - 3)
            m5 = m5 xor (c0 xor mA)
            cF = cF xor (mA xor (c0 shl 3))
            m5 = m5 shl 1 or (m5 ushr 32 - 1)
            cF = cF shl 7 or (cF ushr 32 - 7)
            c0 = c0 xor (m5 xor cF)
            mA = mA xor (cF xor (m5 shl 7))
            c0 = c0 shl 5 or (c0 ushr 32 - 5)
            mA = mA shl 22 or (mA ushr 32 - 22)
            c1 = c1 shl 13 or (c1 ushr 32 - 13)
            mB = mB shl 3 or (mB ushr 32 - 3)
            c6 = c6 xor (c1 xor mB)
            mE = mE xor (mB xor (c1 shl 3))
            c6 = c6 shl 1 or (c6 ushr 32 - 1)
            mE = mE shl 7 or (mE ushr 32 - 7)
            c1 = c1 xor (c6 xor mE)
            mB = mB xor (mE xor (c6 shl 7))
            c1 = c1 shl 5 or (c1 ushr 32 - 5)
            mB = mB shl 22 or (mB ushr 32 - 22)
            m2 = m2 shl 13 or (m2 ushr 32 - 13)
            cA = cA shl 3 or (cA ushr 32 - 3)
            c7 = c7 xor (m2 xor cA)
            mF = mF xor (cA xor (m2 shl 3))
            c7 = c7 shl 1 or (c7 ushr 32 - 1)
            mF = mF shl 7 or (mF ushr 32 - 7)
            m2 = m2 xor (c7 xor mF)
            cA = cA xor (mF xor (c7 shl 7))
            m2 = m2 shl 5 or (m2 ushr 32 - 5)
            cA = cA shl 22 or (cA ushr 32 - 22)
            m3 = m3 shl 13 or (m3 ushr 32 - 13)
            cB = cB shl 3 or (cB ushr 32 - 3)
            m6 = m6 xor (m3 xor cB)
            cC = cC xor (cB xor (m3 shl 3))
            m6 = m6 shl 1 or (m6 ushr 32 - 1)
            cC = cC shl 7 or (cC ushr 32 - 7)
            m3 = m3 xor (m6 xor cC)
            cB = cB xor (cC xor (m6 shl 7))
            m3 = m3 shl 5 or (m3 ushr 32 - 5)
            cB = cB shl 22 or (cB ushr 32 - 22)
            c2 = c2 shl 13 or (c2 ushr 32 - 13)
            m8 = m8 shl 3 or (m8 ushr 32 - 3)
            m7 = m7 xor (c2 xor m8)
            cD = cD xor (m8 xor (c2 shl 3))
            m7 = m7 shl 1 or (m7 ushr 32 - 1)
            cD = cD shl 7 or (cD ushr 32 - 7)
            c2 = c2 xor (m7 xor cD)
            m8 = m8 xor (cD xor (m7 shl 7))
            c2 = c2 shl 5 or (c2 ushr 32 - 5)
            m8 = m8 shl 22 or (m8 ushr 32 - 22)
            c3 = c3 shl 13 or (c3 ushr 32 - 13)
            m9 = m9 shl 3 or (m9 ushr 32 - 3)
            c4 = c4 xor (c3 xor m9)
            mC = mC xor (m9 xor (c3 shl 3))
            c4 = c4 shl 1 or (c4 ushr 32 - 1)
            mC = mC shl 7 or (mC ushr 32 - 7)
            c3 = c3 xor (c4 xor mC)
            m9 = m9 xor (mC xor (c4 shl 7))
            c3 = c3 shl 5 or (c3 ushr 32 - 5)
            m9 = m9 shl 22 or (m9 ushr 32 - 22)
            m0 = m0 shl 13 or (m0 ushr 32 - 13)
            m3 = m3 shl 3 or (m3 ushr 32 - 3)
            c0 = c0 xor (m0 xor m3)
            c3 = c3 xor (m3 xor (m0 shl 3))
            c0 = c0 shl 1 or (c0 ushr 32 - 1)
            c3 = c3 shl 7 or (c3 ushr 32 - 7)
            m0 = m0 xor (c0 xor c3)
            m3 = m3 xor (c3 xor (c0 shl 7))
            m0 = m0 shl 5 or (m0 ushr 32 - 5)
            m3 = m3 shl 22 or (m3 ushr 32 - 22)
            m8 = m8 shl 13 or (m8 ushr 32 - 13)
            mB = mB shl 3 or (mB ushr 32 - 3)
            c9 = c9 xor (m8 xor mB)
            cA = cA xor (mB xor (m8 shl 3))
            c9 = c9 shl 1 or (c9 ushr 32 - 1)
            cA = cA shl 7 or (cA ushr 32 - 7)
            m8 = m8 xor (c9 xor cA)
            mB = mB xor (cA xor (c9 shl 7))
            m8 = m8 shl 5 or (m8 ushr 32 - 5)
            mB = mB shl 22 or (mB ushr 32 - 22)
            c5 = c5 shl 13 or (c5 ushr 32 - 13)
            c6 = c6 shl 3 or (c6 ushr 32 - 3)
            m5 = m5 xor (c5 xor c6)
            m6 = m6 xor (c6 xor (c5 shl 3))
            m5 = m5 shl 1 or (m5 ushr 32 - 1)
            m6 = m6 shl 7 or (m6 ushr 32 - 7)
            c5 = c5 xor (m5 xor m6)
            c6 = c6 xor (m6 xor (m5 shl 7))
            c5 = c5 shl 5 or (c5 ushr 32 - 5)
            c6 = c6 shl 22 or (c6 ushr 32 - 22)
            cD = cD shl 13 or (cD ushr 32 - 13)
            cE = cE shl 3 or (cE ushr 32 - 3)
            mC = mC xor (cD xor cE)
            mF = mF xor (cE xor (cD shl 3))
            mC = mC shl 1 or (mC ushr 32 - 1)
            mF = mF shl 7 or (mF ushr 32 - 7)
            cD = cD xor (mC xor mF)
            cE = cE xor (mF xor (mC shl 7))
            cD = cD shl 5 or (cD ushr 32 - 5)
            cE = cE shl 22 or (cE ushr 32 - 22)
        }
        h[0xF] = h[0xF] xor cB
        h[0xE] = h[0xE] xor cA
        h[0xD] = h[0xD] xor mB
        h[0xC] = h[0xC] xor mA
        h[0xB] = h[0xB] xor c9
        h[0xA] = h[0xA] xor c8
        h[0x9] = h[0x9] xor m9
        h[0x8] = h[0x8] xor m8
        h[0x7] = h[0x7] xor c3
        h[0x6] = h[0x6] xor c2
        h[0x5] = h[0x5] xor m3
        h[0x4] = h[0x4] xor m2
        h[0x3] = h[0x3] xor c1
        h[0x2] = h[0x2] xor c0
        h[0x1] = h[0x1] xor m1
        h[0x0] = h[0x0] xor m0
    }

    override fun toString(): String {
        return "Hamsi-" + (digestLength shl 3)
    }

    companion object {
        private val HOFF384 = intArrayOf(
            0, 1, 3, 4, 5, 6, 8, 9, 10, 12, 13, 15
        )
        private val HOFF512 = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
        )
        private val Tsrc = arrayOf(
            intArrayOf(
                0x466d0c00, 0x08620000, -0x22a30000, -0x45230000,
                0x6a927942, 0x441f2b93, 0x218ace6f, -0x40d3f41e,
                0x6f299000, 0x6c850000, 0x2f160000, 0x782e0000,
                0x644c37cd, 0x12dd1cd6, -0x2d9573ca, 0x32219526
            ), intArrayOf(
                0x29449c00, 0x64e70000, -0xdb50000, -0x3d0d0000,
                0x0ede4e8f, 0x56c23745, -0xc1fbda7, -0x72f2613c,
                0x466d0c00, 0x08620000, -0x22a30000, -0x45230000,
                0x6a927942, 0x441f2b93, 0x218ace6f, -0x40d3f41e
            ), intArrayOf(
                -0x6344e800, -0x4f2d0000, -0x6daf0000, -0x126d0000,
                0x593a4345, -0x1eeb2a0c, 0x430633da, 0x78cace29,
                -0x376cbc00, 0x5a3e0000, 0x57870000, 0x4c560000,
                -0x1567dbcb, 0x75b11115, 0x28b67247, 0x2dd1f9ab
            ), intArrayOf(
                0x54285c00, -0x15130000, -0x3a2a0000, -0x5e3b0000,
                -0x4c5d9890, -0x6b5a3b1f, 0x6bb0419d, 0x551b3782,
                -0x6344e800, -0x4f2d0000, -0x6daf0000, -0x126d0000,
                0x593a4345, -0x1eeb2a0c, 0x430633da, 0x78cace29
            ), intArrayOf(
                0x23671400, -0x37470000, -0xb390000, -0x48b0000,
                0x73cd2465, -0x7595ab7, 0x02c40a3f, -0x23db19e1,
                0x373d2800, 0x71500000, -0x6a200000, 0x0a140000,
                -0x4253e6f7, 0x48ef9831, 0x456d6d1f, 0x3daac2da
            ), intArrayOf(
                0x145a3c00, -0x46170000, 0x61270000, -0xe9f0000,
                -0x319ec294, -0x4fb6c288, 0x47a96720, -0x1e71db3b,
                0x23671400, -0x37470000, -0xb390000, -0x48b0000,
                0x73cd2465, -0x7595ab7, 0x02c40a3f, -0x23db19e1
            ), intArrayOf(
                -0x3694ffd0, -0x18db0000, 0x2f840000, 0x264f0000,
                0x08695bf9, 0x6dfcf137, 0x509f6984, -0x61965098,
                0x26600240, -0x22280000, 0x722a0000, 0x4f060000,
                -0x6c999801, 0x29f944ce, 0x368b63d5, 0x0c26f262
            ), intArrayOf(
                -0x10f4fd90, 0x3afd0000, 0x5dae0000, 0x69490000,
                -0x64f0c3fa, 0x4405b5f9, 0x66140a51, -0x6db0a2f6,
                -0x3694ffd0, -0x18db0000, 0x2f840000, 0x264f0000,
                0x08695bf9, 0x6dfcf137, 0x509f6984, -0x61965098
            ), intArrayOf(
                -0x4bc8ffa0, 0x0c4c0000, 0x56c20000, 0x5cae0000,
                -0x6babe0c1, 0x3b3ef825, 0x1b365f3d, -0xc2ba8a8,
                0x5cb00110, -0x6ec20000, 0x44190000, -0x77740000,
                0x66dc7418, -0x6de0e29a, 0x55ceea25, -0x6da3bb17
            ), intArrayOf(
                -0x1778fe90, -0x628e0000, 0x12db0000, -0x2bde0000,
                -0xd7794d9, -0x56de1abd, 0x4ef8b518, 0x618813b1,
                -0x4bc8ffa0, 0x0c4c0000, 0x56c20000, 0x5cae0000,
                -0x6babe0c1, 0x3b3ef825, 0x1b365f3d, -0xc2ba8a8
            ), intArrayOf(
                -0xb93ffb0, -0x69e80000, 0x14a50000, 0x031f0000,
                0x42947eb8, 0x66bf7e19, -0x635b8f2e, -0x75cbea8c,
                -0x7cd7ff60, 0x67420000, -0x1ee90000, 0x370b0000,
                -0x345cffcc, 0x3c34923c, -0x68984234, 0x450360bf
            ), intArrayOf(
                0x774400f0, -0xea60000, -0xa4e0000, 0x34140000,
                -0x76c88174, 0x5a8bec25, 0x0bc3cd1e, -0x30c88a35,
                -0xb93ffb0, -0x69e80000, 0x14a50000, 0x031f0000,
                0x42947eb8, 0x66bf7e19, -0x635b8f2e, -0x75cbea8c
            ), intArrayOf(
                -0x2b960000, -0x72374000, -0x5a510000, 0x4a290000,
                -0x3b1bd86, -0x364b7994, -0x67c969fc, -0x8b93ce0,
                0x231f0009, 0x42f40000, 0x66790000, 0x4ebb0000,
                -0x124a42d, 0x315cb0d6, -0x1d4e98b6, 0x69505b3a
            ), intArrayOf(
                -0x88afff7, -0x30c34000, -0x3c2a0000, 0x04920000,
                0x029519a9, -0x717c946, 0x7a87f14e, -0x61e967e6,
                -0x2b960000, -0x72374000, -0x5a510000, 0x4a290000,
                -0x3b1bd86, -0x364b7994, -0x67c969fc, -0x8b93ce0
            ), intArrayOf(
                -0x5980ffff, 0x71378000, 0x19fc0000, -0x69250000,
                0x3a8b6dfd, -0x1435510d, 0x2c6d478f, -0x53719378,
                0x50ff0004, 0x45744000, 0x3dfb0000, 0x19e60000,
                0x1bbc5606, -0x1e8d84a3, -0x1e57336a, 0x7b1bd6b9
            ), intArrayOf(
                -0x97ffffb, 0x3443c000, 0x24070000, -0x70c30000,
                0x21373bfb, 0x0ab8d5ae, -0x323a74e7, -0x286a45cf,
                -0x5980ffff, 0x71378000, 0x19fc0000, -0x69250000,
                0x3a8b6dfd, -0x1435510d, 0x2c6d478f, -0x53719378
            ), intArrayOf(
                -0x1130ffff, 0x6f564000, -0xcc20000, -0x58620000,
                -0x424a8de7, -0x48ee143b, 0x4a3b40ba, -0x1540dac,
                -0x64f9fffe, 0x61468000, 0x221e0000, 0x1d740000,
                0x36715d27, 0x30495c92, -0xeecc959, -0x1e32381
            ), intArrayOf(
                0x75c90003, 0x0e10c000, -0x2ee00000, -0x45160000,
                -0x743bd0c2, -0x78a748a9, -0x44d789e3, 0x00b72e2b,
                -0x1130ffff, 0x6f564000, -0xcc20000, -0x58620000,
                -0x424a8de7, -0x48ee143b, 0x4a3b40ba, -0x1540dac
            ), intArrayOf(
                -0x2e9a0000, 0x1bbc0300, -0x61140000, -0x96c0000,
                0x03024527, -0x308f030e, -0x4bbce4e9, -0x7a80c3d5,
                -0x5b3e0000, -0x26c8dc00, 0x0a480000, 0x66610000,
                -0x785ed39, -0x794108a4, -0x5cdb206c, 0x2ba05a55
            ), intArrayOf(
                0x75a40000, -0x3d74d900, -0x6b5c0000, -0x6f0b0000,
                -0x487a820, 0x49ce0bae, 0x1767c483, -0x51209982,
                -0x2e9a0000, 0x1bbc0300, -0x61140000, -0x96c0000,
                0x03024527, -0x308f030e, -0x4bbce4e9, -0x7a80c3d5
            ), intArrayOf(
                -0x47c30000, 0x16710600, 0x379a0000, -0xa4f0000,
                0x228161ac, -0x51b70ebb, 0x66241616, -0x3a3e14c2,
                -0x2db0000, -0x4c3bef00, -0x31100000, -0x31070000,
                0x3c4d7580, -0x72a49b6d, 0x7098b0a6, 0x1af21fe1
            ), intArrayOf(
                0x45180000, -0x5a4ae900, -0x6960000, 0x3b480000,
                0x1ecc142c, 0x231395d6, 0x16bca6b0, -0x20cc0b21,
                -0x47c30000, 0x16710600, 0x379a0000, -0xa4f0000,
                0x228161ac, -0x51b70ebb, 0x66241616, -0x3a3e14c2
            ), intArrayOf(
                -0x1de0000, -0x58a7fb00, 0x25d10000, -0x8a00000,
                -0x76ce8726, 0x1fd4f860, 0x4ed0a315, -0x5edc0061,
                -0xdb00000, -0x1142f600, 0x67a80000, -0x54760000,
                -0x4564b740, 0x0a56dd74, -0x248c1792, 0x1568ff0f
            ), intArrayOf(
                0x0c720000, 0x49e50f00, 0x42790000, 0x5cea0000,
                0x33aa301a, 0x15822514, -0x6a5cb485, -0x4bb4ff70,
                -0x1de0000, -0x58a7fb00, 0x25d10000, -0x8a00000,
                -0x76ce8726, 0x1fd4f860, 0x4ed0a315, -0x5edc0061
            ), intArrayOf(
                -0x398d0000, -0x5072fff4, -0x5b3f0000, 0x218d0000,
                0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173,
                -0x50de0000, 0x7b6c0090, 0x67e20000, -0x725e0000,
                -0x387be1d7, -0x4848bb0d, -0x653b7b0c, -0x74938d43
            ), intArrayOf(
                0x69510000, -0x2b1eff64, -0x3cdd0000, -0x53d10000,
                -0x1b6af452, -0x315bea24, -0x7813d784, -0x431e5c32,
                -0x398d0000, -0x5072fff4, -0x5b3f0000, 0x218d0000,
                0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173
            ), intArrayOf(
                -0x43730000, -0x3c4ffe8, 0x19830000, -0x2ef50000,
                -0x51e7873c, 0x42a69856, 0x0012da37, 0x2c3b504e,
                -0x17230000, -0x5b5ffbc, 0x3c2d0000, -0x44eb0000,
                -0x7f42c9e5, 0x24e81d44, -0x40573d0c, 0x524a0d59
            ), intArrayOf(
                0x54500000, 0x0671005c, 0x25ae0000, 0x6a1e0000,
                0x2ea54edf, 0x664e8512, -0x4045e73d, 0x7e715d17,
                -0x43730000, -0x3c4ffe8, 0x19830000, -0x2ef50000,
                -0x51e7873c, 0x42a69856, 0x0012da37, 0x2c3b504e
            ), intArrayOf(
                -0x1cbd0000, 0x3a4e0014, -0xd3a0000, -0x55b20000,
                -0x24e1bd5a, 0x256bbe15, 0x123db156, 0x3a4e99d7,
                -0x8a60000, 0x19840028, -0x5de70000, -0x11080000,
                -0x3f8ddaea, 0x19981260, 0x73dba1e6, -0x1e7bbda9
            ), intArrayOf(
                0x14190000, 0x23ca003c, 0x50df0000, 0x44b60000,
                0x1b6c67b0, 0x3cf3ac75, 0x61e610b0, -0x24352480,
                -0x1cbd0000, 0x3a4e0014, -0xd3a0000, -0x55b20000,
                -0x24e1bd5a, 0x256bbe15, 0x123db156, 0x3a4e99d7
            ), intArrayOf(
                0x30b70000, -0x1a300000, -0xb0ba000, 0x42c40000,
                0x63b83d6a, 0x78ba9460, 0x21afa1ea, -0x4f5ae7cc,
                -0x49320000, -0x2516fffe, 0x156e8000, -0x256e0000,
                -0x922a59c, 0x36325c8a, -0xd8d1752, -0x59473d73
            ), intArrayOf(
                -0x79870000, 0x3f390002, -0x1e652000, -0x67aa0000,
                -0x6a9a98f2, 0x4e88c8ea, -0x2c22b6bc, 0x161ddab9,
                0x30b70000, -0x1a300000, -0xb0ba000, 0x42c40000,
                0x63b83d6a, 0x78ba9460, 0x21afa1ea, -0x4f5ae7cc
            ), intArrayOf(
                -0x24db0000, 0x09290000, 0x49aac000, -0x7e1f0000,
                -0x350194a7, 0x42793431, 0x43566b76, -0x179345d2,
                0x75e60000, -0x6a99ffff, 0x307b2000, -0x520c0000,
                -0x70cde116, 0x24298307, -0x173b6307, 0x4b7eec55
            ), intArrayOf(
                -0x513d0000, -0x63b0ffff, 0x79d1e000, 0x2c150000,
                0x45cc75b3, 0x6650b736, -0x546d0871, -0x5ceda985,
                -0x24db0000, 0x09290000, 0x49aac000, -0x7e1f0000,
                -0x350194a7, 0x42793431, 0x43566b76, -0x179345d2
            ), intArrayOf(
                0x1e4e0000, -0x21310000, 0x6df80180, 0x77240000,
                -0x13b8f862, -0xb5f96b2, -0x325ce7ee, -0x6755b692,
                -0x4dfa0000, -0x3a970000, 0x28031200, 0x74670000,
                -0x493dc90c, -0x14edc608, 0x33d1dfec, 0x094e3198
            ), intArrayOf(
                -0x53b80000, 0x1ba60000, 0x45fb1380, 0x03430000,
                0x5a85316a, 0x1fb250b6, -0x18d3802, -0x6e1b870a,
                0x1e4e0000, -0x21310000, 0x6df80180, 0x77240000,
                -0x13b8f862, -0xb5f96b2, -0x325ce7ee, -0x6755b692
            ), intArrayOf(
                0x02af0000, -0x48d80000, -0x45e3fd00, 0x56980000,
                -0x4572ba2d, -0x7fb73999, -0x56a3eb66, -0xb091585,
                0x7a8c0000, -0x5a2c0000, 0x13260880, -0x39c30000,
                -0x344c9256, -0x15eb0bd, 0x59d0b4f8, -0x68669e30
            ), intArrayOf(
                0x78230000, 0x12fc0000, -0x56c5f480, -0x6f5b0000,
                0x713e2879, 0x7ee98924, -0xf735f9e, 0x636f8bab,
                0x02af0000, -0x48d80000, -0x45e3fd00, 0x56980000,
                -0x4572ba2d, -0x7fb73999, -0x56a3eb66, -0xb091585
            ), intArrayOf(
                -0x7e620000, -0x13a90000, 0x66320280, -0x6a0d0000,
                0x5da92802, 0x48f43cbc, -0x19a55dd3, -0x71984806,
                0x4d8a0000, 0x49340000, 0x3c8b0500, -0x515d0000,
                0x16793bfd, -0x3090f75c, -0x70e61514, 0x443d3004
            ), intArrayOf(
                -0x33ec0000, -0x5a9d0000, 0x5ab90780, 0x3b500000,
                0x4bd013ff, -0x7864cbe8, 0x694348c1, -0x35a57802,
                -0x7e620000, -0x13a90000, 0x66320280, -0x6a0d0000,
                0x5da92802, 0x48f43cbc, -0x19a55dd3, -0x71984806
            ), intArrayOf(
                0x538d0000, -0x56040000, -0x6108fffa, 0x56ff0000,
                0x0ae4004e, -0x6d3a3207, -0x56bbbfe8, 0x7f975691,
                0x01dd0000, -0x7f580000, -0xb69ffb8, -0x5a000000,
                -0x6f2a815e, -0x281973c9, 0x6612cffd, 0x2c94459e
            ), intArrayOf(
                0x52500000, 0x29540000, 0x6a61004e, -0xf010000,
                -0x65ce8114, 0x452341ce, -0x30a9701b, 0x5303130f,
                0x538d0000, -0x56040000, -0x6108fffa, 0x56ff0000,
                0x0ae4004e, -0x6d3a3207, -0x56bbbfe8, 0x7f975691
            ), intArrayOf(
                0x0bc20000, -0x249d0000, 0x7e88000c, 0x15860000,
                -0x6e02b70d, 0x7581bb43, -0xb9fbb62, -0x2749eb9d,
                -0x7ca60000, -0x3b090000, 0x01470022, -0x11380000,
                0x60a54f69, 0x142f2a24, 0x5cf534f2, 0x3ea660f7
            ), intArrayOf(
                -0x77680000, 0x1f940000, 0x7fcf002e, -0x4b20000,
                -0xea7f866, 0x61ae9167, -0x576a8f94, -0x19ef8b6c,
                0x0bc20000, -0x249d0000, 0x7e88000c, 0x15860000,
                -0x6e02b70d, 0x7581bb43, -0xb9fbb62, -0x2749eb9d
            ), intArrayOf(
                0x07ed0000, -0x4db00000, -0x788bfff6, -0x68f30000,
                0x437223ae, 0x48c76ea4, -0xb879dde, -0x6f8a4e32,
                -0x5d2a0000, -0x598a0000, -0x36bbffec, -0x145d0000,
                -0x3313d185, 0x3018c499, 0x03490afa, -0x64910778
            ), intArrayOf(
                -0x5ac50000, 0x14260000, 0x4e30001e, 0x7cae0000,
                -0x7061f22b, 0x78dfaa3d, -0x8ce9728, 0x0b1b4946,
                0x07ed0000, -0x4db00000, -0x788bfff6, -0x68f30000,
                0x437223ae, 0x48c76ea4, -0xb879dde, -0x6f8a4e32
            ), intArrayOf(
                0x1d5a0000, 0x2b720000, 0x488d0000, -0x509ee800,
                0x25cb2ec5, -0x37864030, -0x7e5dfbd7, 0x1e7536a6,
                0x45190000, -0x54f40000, 0x30be0001, 0x690a2000,
                -0x3d038de7, -0x4e2b7ff3, 0x2dd1fa46, 0x24314f17
            ), intArrayOf(
                0x58430000, -0x7f820000, 0x78330001, -0x3994c800,
                -0x18c8a324, 0x79ad3fdd, -0x538c0191, 0x3a4479b1,
                0x1d5a0000, 0x2b720000, 0x488d0000, -0x509ee800,
                0x25cb2ec5, -0x37864030, -0x7e5dfbd7, 0x1e7536a6
            ), intArrayOf(
                -0x6daa0000, 0x1eda0000, -0x15af0000, -0x174ed000,
                -0x56caa95b, -0x14049e67, -0x4ea3ddac, 0x33c5244f,
                -0x73c60000, -0x25680000, 0x607f0000, 0x54078800,
                -0x7a8ebaed, 0x6006b243, -0x24afc664, -0x75a7195c
            ), intArrayOf(
                0x1e6c0000, -0x3bbe0000, -0x75d20000, -0x43494800,
                0x2c4413b6, -0x74022c26, 0x6a0c1bc8, -0x46623d15,
                -0x6daa0000, 0x1eda0000, -0x15af0000, -0x174ed000,
                -0x56caa95b, -0x14049e67, -0x4ea3ddac, 0x33c5244f
            ), intArrayOf(
                -0x45230000, 0x13ad0000, -0x48190000, -0x8d7d800,
                -0x20baebb3, 0x361ac33a, -0x15a572ec, 0x2a2c18f0,
                -0x47d10000, -0x4ed40000, 0x30d80000, 0x14445000,
                -0x3ea79f5e, 0x3127e8ec, 0x2e98bf23, 0x551e3d6e
            ), intArrayOf(
                0x02f20000, -0x5d7f0000, -0x78c10000, -0x1c938800,
                0x1e1d74ef, 0x073d2bd6, -0x3b3dcdc9, 0x7f32259e,
                -0x45230000, 0x13ad0000, -0x48190000, -0x8d7d800,
                -0x20baebb3, 0x361ac33a, -0x15a572ec, 0x2a2c18f0
            ), intArrayOf(
                -0x1cfa0000, -0x423f0000, -0x78ed0000, -0x400dffa0,
                0x2eba0a1a, -0x724ac8af, 0x73c5ab06, 0x5bd61539,
                0x57370000, -0x350e0000, 0x364e0000, -0x3fddfb80,
                0x56186b22, 0x5ca3f40c, -0x5e6c8071, 0x15b961e7
            ), intArrayOf(
                -0x4bcf0000, 0x77330000, -0x4ea30000, 0x7fd004e0,
                0x78a26138, -0x2ee93ca3, -0x2da92b77, 0x4e6f74de,
                -0x1cfa0000, -0x423f0000, -0x78ed0000, -0x400dffa0,
                0x2eba0a1a, -0x724ac8af, 0x73c5ab06, 0x5bd61539
            ), intArrayOf(
                -0xf3b0000, 0x59230000, 0x45820000, -0x1e72ff40,
                0x3b6d0631, -0x3d12a967, -0x341f01e4, 0x56a7b19f,
                0x16ed0000, 0x15680000, -0x12290000, 0x325d0220,
                -0x1cf3c977, 0x5a4ae643, -0x1c8a0758, -0x7e0206f8
            ), intArrayOf(
                -0x19d80000, 0x4c4b0000, -0x57ab0000, -0x2c2ffd20,
                -0x279ecf48, -0x67584f26, 0x289506b4, -0x28a5b769,
                -0xf3b0000, 0x59230000, 0x45820000, -0x1e72ff40,
                0x3b6d0631, -0x3d12a967, -0x341f01e4, 0x56a7b19f
            ), intArrayOf(
                0x7b280000, 0x57420000, -0x561b0000, 0x634300a0,
                -0x6124bbd1, 0x6d9995bb, 0x27f83b03, -0x38009f10,
                -0x6a450000, -0x7ebb0000, 0x3b240000, 0x48db0140,
                0x0a8a6c53, 0x56f56eec, 0x62c91877, -0x181ff56c
            ), intArrayOf(
                -0x116d0000, -0x29f90000, -0x6d3f0000, 0x2b9801e0,
                -0x6baed784, 0x3b6cfb57, 0x45312374, 0x201f6a64,
                0x7b280000, 0x57420000, -0x561b0000, 0x634300a0,
                -0x6124bbd1, 0x6d9995bb, 0x27f83b03, -0x38009f10
            ), intArrayOf(
                0x00440000, 0x7f480000, -0x25840000, 0x2a230001,
                0x3badc9cc, -0x56496379, 0x030a9e60, -0x41f59862,
                0x5fec0000, 0x294b0000, -0x662e0000, 0x4ed00012,
                0x1ed34f73, -0x4558f737, 0x57140bdf, 0x30aebcf7
            ), intArrayOf(
                0x5fa80000, 0x56030000, 0x43ae0000, 0x64f30013,
                0x257e86bf, 0x1311944e, 0x541e95bf, -0x715b2497,
                0x00440000, 0x7f480000, -0x25840000, 0x2a230001,
                0x3badc9cc, -0x56496379, 0x030a9e60, -0x41f59862
            ), intArrayOf(
                -0x6dd80000, -0x237b0000, 0x57fa0000, 0x56dc0003,
                -0x4516dcea, 0x5aefa30c, -0x6f3108ae, 0x7b1675d7,
                -0x6c450000, 0x3b070000, -0x45ff0000, -0x662ffff8,
                0x3739ae4e, -0x19b3e8de, -0x6907694d, 0x2879ebac
            ), intArrayOf(
                0x01930000, -0x187e0000, -0x12050000, -0x30f3fff5,
                -0x722f72a8, -0x435c4bd2, 0x063661e1, 0x536f9e7b,
                -0x6dd80000, -0x237b0000, 0x57fa0000, 0x56dc0003,
                -0x4516dcea, 0x5aefa30c, -0x6f3108ae, 0x7b1675d7
            ), intArrayOf(
                -0x57260000, -0x69420000, 0x5c1d0000, 0x07da0002,
                0x7d669583, 0x1f98708a, -0x449977f8, -0x25788000,
                -0x54190000, -0x61f30000, -0x50d90000, 0x3d180005,
                0x2c4f1fd3, 0x74f61695, -0x4a3cb815, 0x3c5dfffe
            ), intArrayOf(
                0x033d0000, 0x08b30000, -0xcc60000, 0x3ac20007,
                0x51298a50, 0x6b6e661f, 0x0ea5cfe3, -0x19258002,
                -0x57260000, -0x69420000, 0x5c1d0000, 0x07da0002,
                0x7d669583, 0x1f98708a, -0x449977f8, -0x25788000
            )
        )

        @Suppress("NestedBlockDepth")
        private fun makeT(x: Int): Array<IntArray> {
            val t = Array(256) { IntArray(16) }
            for (y in 0..255) {
                for (z in 0..15) {
                    var a = 0
                    for (k in 0..7) {
                        if (y and (1 shl 7 - k) != 0) a = a xor Tsrc[x + k][z]
                    }
                    t[y][z] = a
                }
            }
            return t
        }

        private val T512_0 = makeT(0)
        private val T512_1 = makeT(8)
        private val T512_2 = makeT(16)
        private val T512_3 = makeT(24)
        private val T512_4 = makeT(32)
        private val T512_5 = makeT(40)
        private val T512_6 = makeT(48)
        private val T512_7 = makeT(56)
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
